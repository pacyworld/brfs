//! tls.zig — OpenSSL TLS wrapper for brfsd peer transport.
//!
//! Provides non-blocking TLS handshake, read, and write over kqueue-driven
//! sockets.  When KTLS is available (FreeBSD KERN_TLS + OpenSSL 3.x with
//! SSL_OP_ENABLE_KTLS), the kernel handles symmetric crypto after handshake
//! — the framed byte stream stays on plain nonblocking kqueue sockets.
//!
//! Design: DANE TLSA-first validation (house rule).  After the handshake
//! completes, the peer certificate is extracted and validated against TLSA
//! records (or CA store as fallback).  OpenSSL's built-in PKIX verification
//! is disabled; we do our own DANE check.
//!
//! mTLS: both server and client contexts present certificates for mutual
//! authentication.  The PSK-based HELLO handshake still runs OVER the TLS
//! channel (defense in depth: TLS proves identity + encrypts; PSK proves
//! cluster membership).

const std = @import("std");
const posix = std.posix;

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
});

/// SSL_OP_ENABLE_KTLS: enables kernel TLS offload on FreeBSD.
/// After handshake, OpenSSL hands session keys to the kernel via
/// TCP_TXTLS_ENABLE/TCP_RXTLS_ENABLE.  Symmetric crypto moves to
/// the kernel and SSL_read/SSL_write become thin wrappers over
/// read/write on the socket.  Silently ignored if unsupported.
const SSL_OP_ENABLE_KTLS: c_ulong = 0x8;

/// Non-blocking event-loop modes.  Without PARTIAL_WRITE an SSL_write
/// that hits backpressure returns WANT_* with an internal pending state
/// pointing at the CALLER's buffer, and the retry must pass the identical
/// pointer — the peer wbuf is an ArrayList that reallocs on append, so a
/// frame queued between attempts moved the pointer and corrupted the TLS
/// record stream (bad record MAC -> mutual conn drop).  Rig-proven
/// 2026-08-29: TLS bursts through delayed links (dummynet/ng_pipe)
/// flapped every 30s while plain TCP was healthy.  PARTIAL_WRITE makes
/// SSL_write consume-and-report like write(2); MOVING_WRITE_BUFFER makes
/// retries safe after a realloc.
const SSL_MODE_ENABLE_PARTIAL_WRITE: c_ulong = 0x1;
const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: c_ulong = 0x2;

/// Result of a non-blocking TLS handshake attempt.
pub const HandshakeResult = enum {
    complete,
    want_read,
    want_write,
};

/// Result of a non-blocking TLS read or write.
pub const IoResult = union(enum) {
    ok: usize,
    want_read,
    want_write,
};

pub const TlsError = error{
    InitFailed,
    CertLoadFailed,
    KeyLoadFailed,
    KeyMismatch,
    HandshakeFailed,
    ReadFailed,
    WriteFailed,
    ConnectionClosed,
    OutOfMemory,
};

// ============================================================================
// TlsContext — shared across all peer connections, created once at startup
// ============================================================================

/// Custom verify callback: always accept.  We do DANE verification ourselves
/// after the handshake completes.
fn alwaysAcceptVerify(_: c_int, _: ?*c.X509_STORE_CTX) callconv(.c) c_int {
    return 1;
}

pub const TlsContext = struct {
    ctx: *c.SSL_CTX,

    /// Initialize a TLS context for both server (accepting) and client
    /// (dialing) roles.  Uses TLS_method() which supports both directions.
    ///
    /// cert_path / key_path: PEM-encoded node certificate and private key.
    /// ca_path: optional CA certificate for chain verification (loaded into
    ///          the trust store for presentation to peers; actual validation
    ///          is DANE-first, not PKIX).
    pub fn init(
        cert_path: [*:0]const u8,
        key_path: [*:0]const u8,
        ca_path: ?[*:0]const u8,
        enable_ktls: bool,
    ) TlsError!TlsContext {
        const method = c.TLS_method() orelse return TlsError.InitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return TlsError.InitFailed;
        errdefer c.SSL_CTX_free(ctx);

        // Load node certificate (full chain if available)
        if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1)
            return TlsError.CertLoadFailed;

        // Load private key
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path, c.SSL_FILETYPE_PEM) != 1)
            return TlsError.KeyLoadFailed;

        // Verify key matches cert
        if (c.SSL_CTX_check_private_key(ctx) != 1)
            return TlsError.KeyMismatch;

        // Load CA certificate for chain presentation (optional)
        if (ca_path) |cap| {
            _ = c.SSL_CTX_load_verify_locations(ctx, cap, null);
        }

        // Request peer certificate for DANE validation.  Custom callback
        // always returns OK — DANE is checked after handshake, not during.
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, &alwaysAcceptVerify);

        // Session ID context (required with SSL_VERIFY_PEER active)
        const sid_ctx = "brfsd";
        _ = c.SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_ctx.len);

        // TLS 1.3 minimum (strongest available; supported by our rig)
        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_3_VERSION);

        // Non-blocking partial-write modes (see constants above).
        _ = c.SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

        // Enable KTLS — offloads symmetric crypto to kernel after handshake.
        // Silently ignored if kernel or library lacks support.
        if (enable_ktls)
            _ = c.SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

        return TlsContext{ .ctx = ctx };
    }

    pub fn deinit(self: *TlsContext) void {
        c.SSL_CTX_free(self.ctx);
        self.ctx = undefined;
    }
};

// ============================================================================
// TlsConn — per-peer TLS connection state
// ============================================================================

pub const TlsConn = struct {
    ssl: *c.SSL,

    /// Create a server-side (accepting) TLS connection.
    /// The fd must already be connected and non-blocking.
    pub fn initServer(ctx: TlsContext, fd: posix.fd_t) TlsError!TlsConn {
        const ssl = c.SSL_new(ctx.ctx) orelse return TlsError.InitFailed;
        errdefer c.SSL_free(ssl);
        if (c.SSL_set_fd(ssl, @intCast(fd)) != 1)
            return TlsError.InitFailed;
        c.SSL_set_accept_state(ssl);
        return TlsConn{ .ssl = ssl };
    }

    /// Create a client-side (dialing) TLS connection.
    pub fn initClient(ctx: TlsContext, fd: posix.fd_t) TlsError!TlsConn {
        const ssl = c.SSL_new(ctx.ctx) orelse return TlsError.InitFailed;
        errdefer c.SSL_free(ssl);
        if (c.SSL_set_fd(ssl, @intCast(fd)) != 1)
            return TlsError.InitFailed;
        c.SSL_set_connect_state(ssl);
        return TlsConn{ .ssl = ssl };
    }

    /// Perform or continue the TLS handshake (non-blocking).
    /// Returns want_read/want_write when the socket isn't ready;
    /// the caller re-arms the appropriate kqueue filter and retries.
    pub fn doHandshake(self: *TlsConn) TlsError!HandshakeResult {
        const ret = c.SSL_do_handshake(self.ssl);
        if (ret == 1) return .complete;

        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            else => {
                drainErrorQueue();
                return TlsError.HandshakeFailed;
            },
        };
    }

    /// Read decrypted data.  With KTLS active this is a thin wrapper
    /// over kernel recvmsg; without KTLS it decrypts in userspace.
    pub fn read(self: *TlsConn, buf: []u8) TlsError!IoResult {
        const ret = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (ret > 0) return .{ .ok = @intCast(ret) };

        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            c.SSL_ERROR_ZERO_RETURN => TlsError.ConnectionClosed,
            else => {
                logSslError("read", err);
                return TlsError.ReadFailed;
            },
        };
    }

    /// Write data.  With KTLS active this is a thin wrapper over
    /// kernel sendmsg; without KTLS it encrypts in userspace.
    pub fn write(self: *TlsConn, data: []const u8) TlsError!IoResult {
        const ret = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (ret > 0) return .{ .ok = @intCast(ret) };

        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            else => {
                logSslError("write", err);
                return TlsError.WriteFailed;
            },
        };
    }

    /// Bytes already decrypted in the SSL internal buffer.
    pub fn pending(self: *TlsConn) usize {
        const ret = c.SSL_pending(self.ssl);
        return if (ret > 0) @intCast(ret) else 0;
    }

    /// Extract the peer's leaf certificate as DER-encoded bytes.
    /// Caller owns the returned memory; null if no peer cert.
    pub fn getPeerCertDer(self: *TlsConn, alloc: std.mem.Allocator) TlsError!?[]u8 {
        const x509 = c.SSL_get0_peer_certificate(self.ssl) orelse return null;
        const der_len = c.i2d_X509(x509, null);
        if (der_len <= 0) return null;

        const buf = alloc.alloc(u8, @intCast(der_len)) catch return TlsError.OutOfMemory;
        errdefer alloc.free(buf);

        var ptr: [*c]u8 = buf.ptr;
        const written = c.i2d_X509(x509, &ptr);
        if (written != der_len) {
            alloc.free(buf);
            return null;
        }
        return buf;
    }

    /// Initiate a clean TLS shutdown (close_notify).
    pub fn shutdown(self: *TlsConn) void {
        _ = c.SSL_shutdown(self.ssl);
    }

    pub fn deinit(self: *TlsConn) void {
        c.SSL_free(self.ssl);
        self.ssl = undefined;
    }
};

fn drainErrorQueue() void {
    while (c.ERR_get_error() != 0) {}
}

/// Rig diagnostics: surface the OpenSSL error behind a failed SSL_read/
/// SSL_write (stderr -> daemon log).  Without this, "read failed"/
/// "write failed" drops are opaque.
fn logSslError(comptime op: []const u8, ssl_err: c_int) void {
    var ebuf: [256]u8 = undefined;
    const code = c.ERR_get_error();
    if (code != 0) {
        c.ERR_error_string_n(code, &ebuf, ebuf.len);
        std.debug.print("brfsd[tls] {s} failed: ssl_err={d} {s}\n", .{ op, ssl_err, std.mem.sliceTo(&ebuf, 0) });
    } else {
        std.debug.print("brfsd[tls] {s} failed: ssl_err={d} (no ssl error queued)\n", .{ op, ssl_err });
    }
    drainErrorQueue();
}

// ============================================================================
// DANE TLSA validation
// ============================================================================

/// DANE TLSA selector (RFC 6698 Section 2.1.2).
pub const TlsaSelector = enum(u8) {
    full_certificate = 0,
    subject_public_key_info = 1,
};

/// DANE TLSA matching type (RFC 6698 Section 2.1.3).
pub const TlsaMatchingType = enum(u8) {
    exact = 0,
    sha256 = 1,
    sha512 = 2,
};

/// DANE TLSA certificate usage (RFC 6698 Section 2.1.1).
pub const TlsaCertUsage = enum(u8) {
    pkix_ta = 0,
    pkix_ee = 1,
    dane_ta = 2,
    dane_ee = 3,
};

pub const TlsaRecord = struct {
    usage: TlsaCertUsage,
    selector: TlsaSelector,
    matching_type: TlsaMatchingType,
    association_data: []const u8,
};

pub const DaneResult = enum {
    dane_ee_match,
    dane_ta_match,
    no_tlsa_records,
    dane_failed,
};

/// Compute SHA-256 fingerprint of DER-encoded certificate.
pub fn certFingerprint(der: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(der, &hash, .{});
    return hash;
}

/// Validate a leaf certificate against TLSA records.
/// Returns no_tlsa_records if the slice is empty (fall back to CA store).
pub fn validateDane(leaf_der: []const u8, tlsa_records: []const TlsaRecord) DaneResult {
    if (tlsa_records.len == 0) return .no_tlsa_records;

    const leaf_fp = certFingerprint(leaf_der);

    for (tlsa_records) |record| {
        if (record.matching_type != .sha256) continue;
        if (record.association_data.len != 32) continue;

        switch (record.usage) {
            .dane_ee, .pkix_ee => {
                if (record.selector == .full_certificate) {
                    if (std.mem.eql(u8, &leaf_fp, record.association_data))
                        return .dane_ee_match;
                }
            },
            .dane_ta, .pkix_ta => {
                // For DANE-TA, we'd check chain certs.  For POC, a
                // DANE-EE pin of the leaf is the expected deployment.
                if (record.selector == .full_certificate) {
                    if (std.mem.eql(u8, &leaf_fp, record.association_data))
                        return .dane_ta_match;
                }
            },
        }
    }
    return .dane_failed;
}

// ============================================================================
// Tests
// ============================================================================

const t = std.testing;

test "certFingerprint: deterministic" {
    const data = "test certificate data";
    const fp1 = certFingerprint(data);
    const fp2 = certFingerprint(data);
    try t.expectEqualSlices(u8, &fp1, &fp2);
}

test "validateDane: no records returns fallback" {
    const result = validateDane("cert", &.{});
    try t.expectEqual(DaneResult.no_tlsa_records, result);
}

test "validateDane: DANE-EE match" {
    const leaf = "leaf certificate data";
    const fp = certFingerprint(leaf);
    const records = [_]TlsaRecord{.{
        .usage = .dane_ee,
        .selector = .full_certificate,
        .matching_type = .sha256,
        .association_data = &fp,
    }};
    const result = validateDane(leaf, &records);
    try t.expectEqual(DaneResult.dane_ee_match, result);
}

test "validateDane: no match returns failed" {
    const leaf = "leaf cert";
    const wrong = [_]u8{0xFF} ** 32;
    const records = [_]TlsaRecord{.{
        .usage = .dane_ee,
        .selector = .full_certificate,
        .matching_type = .sha256,
        .association_data = &wrong,
    }};
    const result = validateDane(leaf, &records);
    try t.expectEqual(DaneResult.dane_failed, result);
}

test "TlsContext: init fails with bad cert path" {
    const result = TlsContext.init("/nonexistent/cert.pem", "/nonexistent/key.pem", null, true);
    try t.expectError(TlsError.CertLoadFailed, result);
}
