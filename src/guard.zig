//! guard.zig — gap #17 mass-delete guard.
//!
//! An accidental `rm -rf` of the replicated tree must not propagate
//! mesh-wide as a tombstone storm.  Both local delete sources funnel
//! through one point (daemon.processDelete): the live event feed AND the
//! rescan floor (scan-derived deletes are journaled as delete work).
//!
//! Policy: count local tombstone transitions in a rolling window; when the
//! count crosses BOTH the absolute floor AND the tree fraction, the guard
//! LATCHES.  While latched, local deletes no longer become tombstones —
//! the records stay live in the content set (the files are gone locally,
//! and the hourly rescan would re-derive the storm, so scan deletes are
//! suppressed too — same choke point).
//!
//! Incoming peer tombstones are UNAFFECTED: the guard protects the mesh
//! from THIS node's catastrophe, never from a peer's deliberate delete.
//!
//! Recovery is operator-driven: `brfsctl massdelete resume` releases the
//! latch and schedules a rescan, which re-derives the suppressed deletes
//! as honest tombstones — an intentional rm -rf still converges, one
//! confirmation later.  The release opens a bypass window: the re-derived
//! storm would otherwise re-trip the guard on its own threshold (rig-
//! proven).  Guard state is in-memory; a restart mid-bypass rearms the
//! guard (and re-trips on the storm — release again).

const std = @import("std");

/// Rolling window for the delete rate.
pub const window_ms: i64 = 10_000;
/// Absolute floor: bulk cleanups of small trees never trip the guard.
pub const floor: u64 = 64;
/// Trip fraction: more than half the live tree deleted inside the window.
pub const pct_num: u64 = 1;
pub const pct_den: u64 = 2;
/// How long an operator release lets deletes through uncounted.
pub const bypass_window_ms: i64 = 120_000;

pub const Decision = enum {
    /// Below the trip conditions: proceed without consulting the tree.
    allow,
    /// Past the absolute floor: the caller must run checkLive() with the
    /// content set's live count (an O(n) walk — kept off the common path).
    check_live,
    /// Latched: the delete is suppressed.
    suppress,
};

pub const Guard = struct {
    window_start_ms: i64 = 0,
    count: u64 = 0,
    latched: bool = false,
    /// Operator-confirmed deletes pass uncounted until this time (the
    /// post-release rescan re-derives the suppressed storm and would
    /// re-trip the guard on its own threshold).
    bypass_until_ms: i64 = 0,

    /// Gate one local tombstone transition (cheap half).  weight is the
    /// delete's blast radius: 1 for a file, 1 + live-descendant count for
    /// a directory (a dir tombstone cascades to the whole subtree on
    /// receivers — rig-proven: the dir tombstone for a 200-file tree
    /// fired before the latch and annihilated the copies anyway).
    pub fn gate(self: *Guard, now_ms: i64, weight: u64) Decision {
        if (now_ms < self.bypass_until_ms) return .allow;
        if (self.latched) return .suppress;
        if (now_ms - self.window_start_ms > window_ms) {
            self.window_start_ms = now_ms;
            self.count = 0;
        }
        self.count +|= weight;
        return if (self.count >= floor) .check_live else .allow;
    }

    /// Expensive half, only past the floor.  live_records is the content
    /// set's live count BEFORE this delete lands.  Returns false when this
    /// delete trips the latch (and is therefore suppressed).
    pub fn checkLive(self: *Guard, live_records: u64) bool {
        if (@as(u128, self.count) * pct_den > @as(u128, live_records) * pct_num) {
            self.latched = true;
            return false;
        }
        return true;
    }

    /// Operator release (`brfsctl massdelete resume`): clear the latch and
    /// open the bypass window so the rescan floor can re-derive the
    /// suppressed deletes without re-tripping.
    pub fn release(self: *Guard, now_ms: i64) void {
        self.latched = false;
        self.count = 0;
        self.window_start_ms = 0;
        self.bypass_until_ms = now_ms + bypass_window_ms;
    }
};

// ---- tests ----

const t = std.testing;

fn storm(g: *Guard, start_ms: i64, live_start: u64, max: u64) u64 {
    // Simulate a delete storm; returns the number of deletes that landed
    // before the guard latched (or max if it never did).
    var live = live_start;
    var landed: u64 = 0;
    while (landed < max and !g.latched) {
        switch (g.gate(start_ms + @as(i64, @intCast(landed)) * 10, 1)) {
            .allow => {},
            .check_live => if (!g.checkLive(live)) break,
            .suppress => break,
        }
        live -= 1;
        landed += 1;
    }
    return landed;
}

test "small-tree cleanup never trips" {
    var g = Guard{};
    // 63 deletes of a 100-record tree: under the absolute floor.
    try t.expectEqual(floor - 1, storm(&g, 0, 100, floor - 1));
    try t.expect(!g.latched);
}

test "rm -rf of a large tree latches" {
    var g = Guard{};
    // 1000-record tree, deletes 10ms apart: the guard must trip around
    // the halfway point, well before annihilation.
    const landed = storm(&g, 0, 1000, 1000);
    try t.expect(g.latched);
    try t.expect(landed >= floor);
    try t.expect(landed < 700);
    // While latched every further delete is suppressed — even after the
    // window would have rolled.
    try t.expectEqual(Decision.suppress, g.gate(1_000_000, 1));
}

test "dir-delete weighting trips on blast radius" {
    var g = Guard{};
    // A single directory delete of a 160-live-descendant subtree in a
    // 201-record tree: weight alone crosses the floor, and 161 > 50% of
    // the live tree trips the latch — the dir tombstone is suppressed.
    try t.expectEqual(Decision.check_live, g.gate(0, 161));
    try t.expect(!g.checkLive(201));
    try t.expect(g.latched);
    // A small dir delete does not trip: weight 5 of 201.
    var g2 = Guard{};
    try t.expectEqual(Decision.allow, g2.gate(0, 5));
}

test "window rolls: spread-out deletes never trip" {
    var g = Guard{};
    // 200 deletes of a 300-record tree, one per two windows.
    var i: u64 = 0;
    while (i < 200) : (i += 1) {
        const d = g.gate(@as(i64, @intCast(i)) * 2 * window_ms, 1);
        try t.expect(d == .allow);
    }
    try t.expect(!g.latched);
}

test "release clears the latch and opens the bypass window" {
    var g = Guard{};
    _ = storm(&g, 0, 200, 200);
    try t.expect(g.latched);
    g.release(1_000_000);
    try t.expect(!g.latched);
    try t.expectEqual(@as(u64, 0), g.count);
    // Inside the bypass window the re-derived storm passes uncounted.
    try t.expectEqual(Decision.allow, g.gate(1_000_001, 500));
    try t.expectEqual(Decision.allow, g.gate(1_000_001 + bypass_window_ms - 1, 1));
    try t.expect(!g.latched);
    // After the window the guard is armed again.
    _ = storm(&g, 1_000_001 + bypass_window_ms, 200, 200);
    try t.expect(g.latched);
}
