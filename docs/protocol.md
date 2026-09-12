# BrFS peer protocol (POC)

Full mesh, framed binary over TCP on a trusted LAN. Every message is
length-prefixed. All operations are idempotent: receiving the same message
twice, or a FETCH for a file already at that version, is a no-op — retries
are trivially safe.

## Framing

```
+--------+--------+-----------------------------------+
| len:32 | op:16  | payload ...                       |
+--------+--------+-----------------------------------+
```

`len` covers op + payload and MUST NOT exceed BRFS_MAX_FRAME (16 MiB); a
peer sending a larger frame is dropped. `op` is one of the opcodes below.

## Byte layouts

All integers are big-endian. Strings (paths, node_id, psk) are
length-prefixed with a u16 unless noted. `path` is always relative to the
replicated root and validated on receipt (see below). `ver` is the pair
`(origin u64, seq u64)`; `origin` is fnv1a64(node_id) of the node where the
change was made. `flags` bit0 = ISDIR. Implemented by src/protocol.zig —
the codec is the authority; keep this table in sync.

```
HELLO        proto u16 | node_id | psk | nonce [16]
ANNOUNCE     ver | flags u16 | mode u16 | size u64 | mtime_sec i64 |
             mtime_nsec u32 | path | sha256 [32]
FETCH_REQ    ver | offset u64 | len u32 | path
FETCH_DATA   ver | offset u64 | path | data (u32 len + bytes)
FETCH_ACK    ver | path | sha256 [32]
TOMBSTONE    ver | flags u16 | path
RESYNC_REQ   journal_wm u64  (requester's contiguous applied journal seq
                               for this sender; 0 = full pull.  Doubles as
                               the sender's ack-horizon evidence: "I settled
                               your journal through N" — D35)
RESYNC_ENTRY ver | flags u16 | state u8 | mode u16 | size u64 |
             mtime_sec i64 | mtime_nsec u32 | path | sha256 [32] |
             jseq u64   (sender's journal seq when journal-sourced, else 0)
MOVE_FROM    ver | flags u16 | cookie u32 | path
MOVE_TO      ver | flags u16 | cookie u32 | path
NACK         ver | code u16 | path
RESYNC_DONE  count u64 | journal_head u64
                          (terminates a RESYNC stream; receiver runs its
                          post-join scan; journal_head settles the
                          requester's new watermark for this sender, and is
                          0 only when the sender has no journal at all)
WM_ECHO      journal_wm u64  (D35: the stream receiver echoes its newly
                           settled watermark back to the streamer — sent
                           exactly where the receiver persists it: the lazy
                           4096-entry boundary and the DONE settle)
```

RESYNC_ENTRY carries `state` (1=live, 2=deleted) so tombstones propagate
during catch-up. Rename cookie 0 is a valid cookie (first rename after
boot); pair by cookie value, not by "nonzero".

**The version vector is gone (v3).** Its pull role was replaced by the
journal watermark in Phase 3b, and its survived-empty vestige left the
tombstone-GC ack horizon TTL-only. D35 re-founded the horizon on claims
about whole journals instead of per-origin maxima (see below); a coarse
per-origin max over-covers records a mid-burst conn drop never delivered
— the same unsoundness that made vector-diff resync lose 934 records
(rig-proven 2026-08-28).

## Watermark-diff RESYNC (Phase 3b, protocol v2)

Each node keeps, per mesh peer, the **highest contiguous journal seq it
received-and-applied from that peer** (persisted in the LMDB meta DBI as
`wm_<peer-origin>` keys; durable across restarts).  On RESYNC_REQ the
requester advertises that value as `journal_wm`:

- **`journal_wm == 0`** (first contact, wiped state): full-record pull —
  the sender streams every record (idempotent apply fetches the holes).
- **Watermark usable** (`0 < wm <= sender head`, sender's oldest retained
  journal seq `<= wm+1`): the sender streams `journalTail(wm+1)` in seq
  order as RESYNC_ENTRYs with `jseq` set, in chunks (a fresh LMDB read txn
  per chunk — a long stream never pins the freelist), then RESYNC_DONE
  with its head at stream start.
- **Watermark unusable** (sender's journal GC'd past it, rebuilt journal,
  or `wm` ahead of the head): silent full-pull fallback.  The RESYNC_DONE
  still carries `journal_head`, so the requester's very next RESYNC can
  journal-diff.

**The served head is the COMMITTED head, not the in-memory one.** LMDB
read txns cannot see the sender's pending write txn; serving by the
in-memory seq would read an empty tail yet still settle the requester's
watermark past it (rig-proven: an online burst's tail vanished this way
for a rejoining peer). `journal_committed` advances at every flush, and
the daemon's checkpoint pass pushes each newly-durable tail to every peer
it has served (full-pull reseed if that peer's watermark went
undiffable), so no serve ever waits for a reconnect to finish a window.
Watermarks therefore never overtake durable state anywhere.

**Dir renames are journaled per-descendant.** A wire rename moves the top
entry; every member additionally rewrites each live descendant's record
to the new path under the rename's version (identically on all nodes, so
no per-child wire traffic is needed), tombstones the old paths, and —
receiver side only — retargets in-flight child installs and re-fetches
bytes that never landed. Because the sender's translation is itself
journaled, diff streams carry the child rows: an offline joiner fetches
`new/child`, never a NACK'd `old/child`.

Contiguity is the soundness argument and it is why this mode cannot
repeat the vector catastrophe: journal seqs are per-sender monotonic and
the stream is applied in wire order, so the requester's persisted
watermark NEVER wraps around unapplied entries.  A conn drop mid-stream
truncates, the in-flight high-water dies with the conn, and the next
RESYNC_REQ resumes from the last persisted (or DONE-settled) watermark —
replayed prefix entries are idempotently ignored.  Watermarks persist
lazily (every 4096 applied entries during a stream, always at DONE),
folded into the regular checkpoint batch: a crash replays at most one
4096-entry prefix at the next connect.

Per-path semantics inside a diff stream are identical to a full pull
(`entryAction`: fetch/adopt/tombstone/ignore by `relate()` on versions);
announce traffic interleaved with a stream is reconciled by the same rule.
A journal-diff stream of 0 entries is legal and converges immediately.

## Ack-horizon revival (D35, protocol v3)

Tombstones are collectable early (before their 7-day TTL) once every
configured member provably holds the delete. The claim currency is the
same watermark machinery:

- Every content-set write stamps its record with the local journal seq of
  its own mutation (`Record.journal_seq`, persisted in the record value;
  pre-D35 values decode as 0 = provenance unknown, never early-collected).
- A member **claims** coverage of another node's journal through N in two
  places: `RESYNC_REQ.journal_wm` (at every stream start) and **WM_ECHO**
  (from the receiver back to the streamer at the exact points it settles
  a watermark — the 4096-entry lazy-persist boundary and the DONE
  settle). Claims therefore flow with activity; an idle mesh sends
  nothing, and the checkpoint tail-push gives a healthy mesh a stream to
  echo over at every commit batch.
- The sender keeps the LATEST claim per member (never the max — a
  regressed claim means the member's state was rebuilt and its full pull
  re-covers everything first).
- `gcTombstones` early-collects a tombstone with `journal_seq = s` iff
  every claim is >= s and every configured peer has claimed at least once.
  Claims are contiguous-by-construction "I applied your journal through
  N" proofs, which is the hole-free soundness the per-origin-MAX vector
  could never give.

Early collection is belt-and-suspenders safe against delivery loss: the
tombstone leaves the records DBI but its journal entry lives on (1M-entry
retention), so any peer that later claims below s re-learns the delete
from a diff stream. Only journal GC of the entry AND a member never
rising past it yields the same stray-resurrection class the TTL window
already documents.

Decoding is strict: every byte of the payload must be consumed
(TrailingGarbage), every length field must fit the frame (Truncated), and
paths must pass the validation below before ANY filesystem use.

## Versions

A file's version is the pair `ver = (origin_node, origin_seq)`:
`origin_node` is the node_id of the member where the change was made;
`origin_seq` is a persistent, per-node, strictly monotonic counter
incremented on every local mutation. Clock time plays no role in ordering
— NTP skew cannot break convergence (T18 verifies).

- Same origin, higher seq → newer (normal update).
- Different origins where neither version subsumes the other → **conflict**.
  Deterministic LWW on all members: higher `(origin_seq, origin_node)` wins;
  the losing content moves to `/var/db/brfs/conflicts/` (quarantine), never
  silently dropped.
- Receiving an already-known or older version is a no-op (idempotency).

## Opcodes

| op | name        | payload | notes |
|----|-------------|---------|-------|
| 1  | HELLO       | node_id, protocol version, PSK, nonce | handshake; nonce prevents replay |
| 2  | ANNOUNCE    | path, op-flags, size, mtime, sha256, ver | flags carry ISDIR |
| 3  | FETCH_REQ   | path, ver, offset, len | receiver-driven pull: one chunk in flight per fetch (flow control) |
| 4  | FETCH_DATA  | path, ver, offset, len, data | one requested chunk; empty data at offset==size completes a 0-byte file |
| 5  | FETCH_ACK   | path, ver, sha256 | post-install hash re-verify |
| 6  | TOMBSTONE   | path, ver, ISDIR | delete |
| 7  | RESYNC_REQ  | journal_wm | joining node → peer; also the ack-horizon claim |
| 8  | RESYNC_ENTRY| path, ISDIR, size, mtime, sha256, ver, jseq | peer → joining node |
| 9  | MOVE_FROM   | path, ver, cookie, ISDIR | rename source |
| 10 | MOVE_TO     | path, ver, cookie, ISDIR | rename destination |
| 11 | NACK        | path, ver, error code | explicit failure; never silently drop |
| 12 | RESYNC_DONE | count, journal_head | stream terminator; receiver settles watermark, runs post-join scan |
| 13 | WM_ECHO     | journal_wm | settled-watermark echo to the streamer (D35 ack horizon) |

## Directories

Empty directories replicate via ANNOUNCE with ISDIR (created on receipt).
Directory delete = TOMBSTONE with ISDIR. A directory rename is a MOVE pair
with ISDIR; the receiver rewrites the subtree paths in its content set
descendant-by-descendant (T12 covers a populated-subtree rename).

## Metadata policy (POC)

Replicated: mode bits and mtime. NOT replicated: uid/gid (content is owned
by the service user on each node), ACLs, flags, xattrs, symlinks, devices.
ATTRIB kernel events drive metadata-only ANNOUNCEs (mode/mtime).

## Write stability

The journal debounces: a file is hashed and announced only after a
quiet period (no MODIFY for N ms) or CLOSE_WRITE. Hashing runs on the
completion worker, never on the core loop: the core submits a stat
snapshot, and the announce is published from the completion callback
only when a fresh stat still matches the snapshot (otherwise the job is
re-driven). The unchanged fast path skips hashing entirely when the full
stat identity (size, mode, mtime, inode) matches the stored record —
residual hole: an in-place rewrite that then restores mtime via
utimensat(2) evades detection until the next change or rescan (the
rescan floor hashes suspicious entries and repairs). After transfer, the
receiver's FETCH_ACK includes the sha256 of what it installed; a mismatch
requeues.

## Wire path validation (non-negotiable)

All paths in incoming messages are validated before ANY filesystem use:
relative to the replicated root, no empty components, no `.`/`..`
components, no leading `/`. Violations are dropped and the peer is
demoted (logged; repeated violations = disconnect).

## Fetch source selection (gap #10)

A fetch goes to the peer whose ANNOUNCE/RESYNC_ENTRY started it (the
presumed holder). A NACK for the *current* fetch attempt is handled by
code: `missing` (the source does not hold the record/version) triggers a
**source fallback** — the receiver keeps its staged bytes and resumes the
pull at the current offset from another ready peer (full mesh: any
converged peer can serve; tried-sources are tracked per fetch so fallback
never loops; when every ready peer has been tried, the fetch aborts and
the stall sweep / next ANNOUNCE / RESYNC re-drives it). `stale` (the
record moved on at the source) aborts the fetch — the NACKer re-ANNOUNCEs
the fresh version, which re-drives the pull. A NACK whose version does not
match the current attempt is ignored (superseded attempts must not kill a
fresh fetch).

## Ordering

Per-path monotonic versions; out-of-order arrivals are dropped if older,
queued if newer.

## Self-echo suppression

Events generated by the local installer (staging rename into the tree)
must NOT re-announce. Install operations are marked in the journal and the
resulting rename-into-place event is swallowed. This is the classic DFSR
loop hazard; it is covered by test T7.

## Security (POC)

Bind to a trusted interface; HELLO carries a pre-shared key + nonce.
TLS/mTLS is Phase 2 (promoted from Phase 3 on 2026-08-24: users WILL run
this across the public internet, and compliance regimes require encrypting
all data in motion, LAN/VPN included).  House TLS rules apply: DANE TLSA
validation primary, local CA trust store as fallback, DNSSEC ignored;
Pacy World CA (OpenBao-issued) node certificates.  The framed codec above
is transport-agnostic — TLS wraps the byte stream without touching
framing.
