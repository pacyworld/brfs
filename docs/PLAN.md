# BrFS (BSD Replicated File System) — DFSR-style Replicated Folder Engine for FreeBSD

Status: IMPLEMENTATION (v0.8, 2026-08-25) — Phase 0 + Phase 1 complete
(POC end-to-end: T1-T8 + T10 green on the 3-VM rig, commit fb4b1b5);
Phase 2 underway: LMDB content-set swap landed (gaps #7/#9/#12 closed),
daemon hardening landed (async install completion + brfsctl socket),
kernel hardening part 1 landed (epoch unload drain, move-out unflag,
hourly ADDROOT re-push)
Name: FINAL — **BrFS** ("Brrr... it's cold"). Daemon: `brfsd`, kmod: `brfs.ko`, utility: `brfsctl`.
Owner: Daniel
Target: FreeBSD 15.0+ (VFS event notification points / inotify landed 15.0-RELEASE)
Runs atop: UFS2 or ZFS — filesystem-agnostic, a SERVICE over the VFS, not a filesystem
Hosting: Forgejo PRIMARY (pacyworld.dev, Pacy World org) + GitHub MIRROR
Test env: 3 bhyve VMs on freebsd-dev1.morante.com (zvols on **vault pool** — Storage pool ~94% full)
Driver use case: replace cdn-sync.sh (rsync+lockf cron hack) for Pacy World CDN replication

## v0.4 locked decisions (2026-08-23)

1. **CAP: AP, multi-master, eventual consistency.** Raft REJECTED for the data
   path (CP consensus blocks writes during partition; wrong tradeoff for CDN).
   v1 membership = static config, no consensus needed anywhere.
   Raft-for-membership deferred post-POC.
2. **Minimum hosts: 2 members, NO quorum.** Design N-member full-mesh; POC on 3 VMs.
3. **Conflicts: LWW (ver, node_id) tiebreak + QUARANTINE** — loser moved to
   /var/db/brfs/conflicts/ (ConflictAndDeleted analog, OUTSIDE the replicated
   tree). Supersedes v0.3 "loser dropped in POC".
4. **brfs.ko is REQUIRED — single change-feed backend.** No inotify runtime
   backend, no backend= config knob, no escape hatch. inotify demoted to
   dev/test oracle tooling (inotify-tools, share/examples/inotify, dtrace
   vfs::vop_inotify probes).
5. **Rename is first-class**: kernel emits cookie-paired IN_MOVED_FROM/
   IN_MOVED_TO (global atomic inotify_rename_cookie) — protocol carries
   MOVE_FROM/MOVE_TO(cookie); no create+delete artifacts.
6. **Channel: /dev/brfs cdev + batched read** (bpf/auditpipe-proven pattern,
   ~1M ev/s ceiling). mmap shared ring = Phase 3+ drop-in optimization
   (record layout stays mmap-compatible; SPSC drainer-thread model chosen for
   it). Netlink kept on the board ONLY for multi-consumer (e.g. brfsctl live
   tail). Rejected: custom EVFILT filter (kevent carries no payload), devd,
   sysctl/ioctl polling, auditpipe, EVFILT_VNODE.
7. **brfsd is single-process, multi-threaded** (one drainer thread owns ring
   pop — preserves mmap SPSC discipline; workers via pipe-trick wakeup).
   Multi-process brfsd considered-and-rejected (feed is single-consumer;
   content set needs single owner; Capsicum-in-one-process is the privsep
   answer if a security review demands it).
8. **brfsctl utility** (/var/run/brfsd.sock in Phase 1): status, peers,
   backlog, resync [path], conflicts list|restore|prune, journal stats;
   sysctl-backed `stats` works standalone from day one.
9. **Jails/nullfs**: nullfs interop both directions inherited via the
   VOP-dispatch-layer tap; jails can't kldload → kmod on host kernel, jailed
   brfsd consumes /dev/brfs via devfs ruleset; registration resolves in the
   caller's namespace to the same vnode/fileid; kmod filters by dir fileid
   lineage (mount-alias-agnostic); containment falls out free (a jail can
   only register what it can resolve); ONE brfsd per kernel (single-open) →
   multi-node tests need separate bhyve VMs, not jails sharing a kernel.
10. **Layered catch-up durability** (ring = accelerator, never dependency):
    (a) brfsd restart, kmod alive → ring backlog drain, resume from
    last-consumed seq (USN analog); (b) ring overflow → overflow flag →
    targeted tree rescan; (c) first start / kmod reload / reboot → startup
    scan vs persisted content set (stat compare, hash only suspicious),
    synthesize delta events; (d) node offline → peer RESYNC via HELLO
    version exchange. Phase 3 durable on-disk journal replaces scans with
    tail-from-seq.
11. P0.0 (autodo UAF fix) DONE: mac_do_auto v0.3.1 shipped, port merged
    (deluxe PR #239 + extra_ports), man pages, prod-installed on freebsd-dev1.

## Kernel mechanism (verified in local 15.x /usr/src)

- Notification points are flag-gated macros in sys/inotify.h in VOP
  pre/post-hooks: INOTIFY(vp, ev) self events; INOTIFY_NAME(vp, dvp, cnp, ev)
  named events; INOTIFY_MOVE (rename cookie pair); all gate on
  vn_irflag_read() & (VIRF_INOTIFY|VIRF_INOTIFY_PARENT) → VOP_INOTIFY(vp, dvp,
  cnp, event, cookie), default vop_stdinotify → vn_inotify().
- Events fire at the VOP dispatch layer → one tap covers UFS + ZFS +
  NFS-server-side accesses (article dtrace stack: nfsrvd_read → vop_read_post
  → VOP_INOTIFY_APV) + nullfs both directions. Zero cost when BrFS is not
  running (flag unset → single predictable-false branch).
- Hardlink nuance: names via namecache, event may carry a different link's
  name → filter by dir fileid lineage + cnp name at tap.
- **Tap design (P0.2 spike finalizes)**: (1) interpose vop_inotify in fs vop
  vectors (ufs_vnodeops, ZFS vnop tables — plain fn-ptr structs, save/restore
  on load/unload), prefix-filter by registered roots, emit to ring, call
  through to vop_stdinotify; (2) keep gate flags set for vnodes under
  registered roots — VIRF_INOTIFY_PARENT propagation to new child vnodes is
  THE open spike question (struct inotify_softc opaque → no kernel-side
  watch; expect direct v_irflags manipulation + propagation at lookup/create);
  (3) NO-GO fallback = small owned kernel patch (registration API,
  upstreamable), NEVER an inotify userland backend.

## brfs.ko (C — event tap + delivery only; no logic, no file-format parsing)

- /dev/brfs cdev + mtx-protected fixed-size ring of struct brfs_event
  { seq, op, cookie, dir_fileid, fileid, name }. NO path resolution in kernel
  (vn_fullpath self-deadlock lesson). read() blocks via msleep; poll via
  selrecord + KNOTE_UNLOCKED; brfsd kqueue EVFILT_READ with EV_CLEAR, batched
  drain.
- Single-open guard (atomic, EBUSY). ioctl push at daemon startup (watch
  roots, event mask — AUTODO_SET_POLICY pattern). security.brfs.* sysctls
  (enabled, event_count, ring_drops, log_events, ring_size, test_event).
- Safety bar (autodo UAF lessons): ring MALLOC'd MOD_LOAD, freed MOD_UNLOAD
  after asserting no open fd; unload drains knotes, wakes readers ENXIO; zero
  hot-path MALLOC; witness/dtrace audits; T9 load/unload/reload stress.
- Ring size is a DURABILITY parameter (bounds safe brfsd downtime before a
  scan) — sysctl/tunable at load; default from P0.2 measured event rates.

## brfsd (Zig — all replication logic)

- kqueue event core (EV_CLEAR conns, staged changelist, pipe-trick wakeup,
  close(pipe_wr) broadcast shutdown — house async rules; McpBridge event core
  = proven template). Zig I/O: prefer ZIO (lalinsky) or std.Io.Threaded; pin
  zig version at scaffolding (mac_do_auto zig:015; McpBridge hit 0.16
  breakage).
- Modules: events.zig (/dev/brfs consumer + ioctl setup — ONLY detection
  path), contentset.zig ({id, ver, size, mtime, sha256, state}; LMDB-backed
  since Phase 2 — vendored LMDB 1.0.0 in lib/lmdb, static, hash-verified
  against databases/lmdb distinfo; the in-memory map stays the query layer,
  LMDB is the write-through durable store under state_dir/csdb),
  journal.zig (per-path coalescing), protocol.zig (mutation-tested codec,
  securemilter-lib pattern), peer.zig/server.zig (full mesh,
  retries/backoff, PSK-in-HELLO POC, TLS/mTLS Phase 2), installer.zig (staging +
  atomic rename + echo suppression + quarantine), resync.zig, config.zig
  (UCL via base-system privateucl, sole consumer), ctl.zig (brfsd.sock
  server).

## Protocol (POC, full mesh, trusted LAN, PSK)

Framed binary length-prefixed: HELLO(node_id, version, psk),
ANNOUNCE(path, op, size, mtime, sha256, ver), FETCH_REQ/DATA/ACK,
TOMBSTONE(path, ver), RESYNC_REQ/ENTRY, MOVE_FROM/MOVE_TO(cookie) rename
pairs. All ops idempotent. See docs/protocol.md.

## Correctness rules (non-negotiables)

1. Atomic install (staging + rename(2), same-fs verified at startup).
2. Idempotent everything.
3. LWW (ver, node_id), loser → quarantine, ≤1 generation divergence.
4. Per-path coalescing.
5. Per-path monotonic ordering (older dropped, newer queued).
6. Self-echo suppression (installer's rename never re-announces — T7).
7. Wire path validation: every path in an incoming message is validated
   (relative to root, no empty/./.. components, no leading /) before ANY
   filesystem use (T16 hostile-peer test).
8. Version derivation: ver = (origin_node, origin_seq), persistent per-node
   monotonic counter — no wall-clock in ordering (T18 clock-skew test).
9. Metadata policy: mode+mtime replicated; uid/gid NOT (service user owns
   content per node); no ACL/xattr/symlink/device in POC.

## Phases

- Phase 0 spikes: ALL DONE. P0.0 (autodo UAF fix); P0.1 notification-point
  characterization (findings below, GO); P0.2 GATING kmod spike (tap +
  flags + ring + /dev/brfs — GO, findings below); P0.3 bhyve 3×VM rig on
  vault pool (RUNNING: brfs-a/b/c, vmctl-brfs); P0.4 repo scaffolding.
- Phase 1: POC end-to-end ON brfs.ko from day one. T1–T8 green on 3 VMs with
  mid-test daemon restarts. **DONE 2026-08-24 (fb4b1b5)**: T1–T8 + T10 PASS
  (tests/vm/repl-tests.sh), tap-smoke green on all 3 VMs after.
  ~~Known POC limitation: big-file install blocks the core loop (fsync)~~ —
  RESOLVED in Phase 2 (completion worker, see below).
- Phase 2: kernel hardening — fidelity vs dtrace oracle, ring sizing/drop
  behavior, overhead measurement, T9 matrix, unload veto while fd held.
  **LMDB content-set swap DONE 2026-08-24** (closes design-review gaps
  #7/#9/#12):
  - contentset.zig persistence is now LMDB (vendored 1.0.0, lib/lmdb,
    statically linked — no guest pkg dependency).  Every flush/checkpoint
    is ONE write-txn commit (records + ring-seq checkpoint + local seq
    counter atomic + fsync'd) → gap #12 crash consistency by construction;
    torn-tail machinery deleted.  A corrupt env is moved aside
    (csdb.corrupt-<ts>) and rebuilt via the scan/RESYNC floor.
  - Gap #7 tombstone retention/GC: tombstones are durable first-class keys
    carrying deleted_at (wall-clock retention stamp, NEVER ordering).
    gcTombstones() runs hourly from the daemon timer and drops tombstones
    older than 7 days (DFSR ConflictAndDeleted window).  The second half
    of the locked retention rule — all-member-ack horizon — lands with
    per-member ack tracking (still open; TTL alone is DFSR-equivalent).
  - Gap #9 delete-vs-modify rule LOCKED: pure LWW on (seq, origin).  A
    winning offline modify (M > tombstone N) RESURRECTS the file (fetch/
    install over the tombstone; the deleting side has no copy to
    quarantine); a winning tombstone quarantines the divergent live copy
    (installer.quarantine, existing ConflictAndDeleted behavior).  Pinned
    by unit tests in contentset.zig and resync.zig; T19 is the rig proof.
  - Gotchas (accepted, documented): fixed 1 GiB map (sparse; MDB_MAP_FULL
    runbook: stop brfsd, `mdb_copy -c csdb csdb.compact`, swap, start);
    csdb shares state_dir's free-space precondition with quarantine
    (gap #18); relative paths limited to 480 bytes (LMDB 511-byte key cap;
    digest-key scheme is Phase 3 material if ever needed).  No migration
    from the POC log/snapshot format — POC state is throwaway, the scan
    floor rebuilds.
  - LMDB ≠ the Phase 3 durable journal: the content set is current-state
    KV (RESYNC diff source); the journal (tail-from-seq replay) still
    arrives in Phase 3 and coexists.
  **Daemon hardening DONE 2026-08-24** (second Phase 2 daemon commit):
  - Installer fsync/rename OFF the core loop: complete() split into
    beginComplete (core: incremental-hash final, fstat, detach) +
    finishComplete (single FIFO completion worker: fsync, divergent-dest
    hash+quarantine, rename, meta).  The 200MB-install core-loop stall
    (~30-70s, mesh-snowballing) is gone; the rig log shows the core loop
    processing the install's own kernel events 19ms after handoff.
    Ordering rules that keep async completion correct: an in-flight or
    completing fetch is the effective stored version for both ANNOUNCE and
    RESYNC_ENTRY (the resync path was the hole — a restart pull from TWO
    peers double-fetched, and the duplicate jobs shared one staging path:
    second rename -> FileNotFound); a completion result landing under a
    newer stored record is reverted on disk; one install's MOVE_TO+ATTRIB
    events are swallowed by an O(1) fileid/gen identity marker (persisting
    until the completion callback — NO re-hash of the installed file on the
    core loop).
  - brfsctl control socket /var/run/brfsd.sock (0600, unix, text protocol:
    one-line request, response until EOF): status, peers, backlog, journal,
    resync, conflicts list|restore <name>|prune [substr].  Handled on the
    core kqueue (no threads); responses capped at 16KB.  Restore renames
    the quarantined file back into the tree WITHOUT an echo marker — the
    tap announces it as fresh local content (operator override semantics).
    Covered by the ctl smoke block in tests/vm/repl-tests.sh.
  **Kernel hardening (part 1) DONE 2026-08-25**:
  - Epoch-style unload drain: every tap invocation runs inside a
    preemptible epoch section (epoch_enter_preempt; the tap may sleep —
    GETATTR, v_addpollinfo); MOD_UNLOAD restores all patched vectors and
    then epoch_wait_preempt() gives a HARD drain guarantee, replacing the
    pause(hz) grace.
  - Move-out unflag: vnodes renamed OUT of watched trees are stripped at
    MOVE_FROM (files: VIRF_INOTIFY_PARENT immediately, guarded by
    no-genuine-watches on the source parent; dirs: VIRF_INOTIFY + PARENT
    immediately + deferred unflag subtree walk that also strips child
    PARENT flags when the parent was stripped by us).  MOVE_TO re-flags
    only when the DESTINATION parent is flagged (the INOTIFY_MOVE gate
    passes via the source parent too — an unconditional re-flag would
    undo the strip).  Rig-found and fixed en route (dtrace + kmod
    log_events on brfs-a): (a) the unflag walk's own readdirs fire
    IN_ACCESS back into the tap (vop_readdir_post), whose upgrade-on-
    sight re-flagged just-stripped dirs via their lingering PARENT flag —
    upgrade-on-sight is now MUTATION-ONLY and the dir's PARENT is
    stripped alongside INOTIFY; (b) cache_enter at the rename destination
    runs BEFORE the post-hook, so the MOVE_FROM strip removed the fresh
    flag for in-tree renames — the MOVE_TO half now re-establishes PARENT
    unconditionally when the destination parent is flagged.
  - Watch-removal flag-strip decision: DECIDED — daemon-side periodic
    idempotent ADDROOT re-push (hourly, daemon.zig timerPass).  A
    kernel-side flag refcount is infeasible: struct inotify_softc is
    opaque and watch removal cannot be interposed.
  - Verified: 60 host unit tests + kmod compile check; extended
    tap-smoke.sh (new move-out/move-back-in battery) PASS on all 3 VMs;
    repl-tests.sh T1–T8+T10 + ctl smoke PASS on the rig after redeploy.
  **Daemon correctness fixes 2026-08-26** (found by the new
  ring-overflow rig test + T5 stress):
  - Version-seq preallocation (crash safety): the persisted meta
    local_next_seq is now a RESERVED CEILING kept seq_reserve_window
    (65536) ahead of the next issuable seq — bumped at open and topped
    up at every commit; nextVersion() force-commits and re-reserves if a
    burst exhausts the window.  Before, announces between flushes were
    lost on kill -9 and the restarted daemon re-issued already-announced
    (origin, seq) versions for DIFFERENT paths — peers dropped them as
    duplicates and LWW diverged (rig-proven with a 6000-file storm).
  - Rescan in-flight guard: resync.scan() takes an InFlight predicate
    (daemon's incoming map) and never announces/tombstones paths the
    fetch/install machinery owns.  Before, an install-storm ring
    overflow → rescan re-origined in-flight installs as fresh LOCAL
    versions (2058 phantom announces on the rig); three files whose
    origin seqs lost LWW were tombstoned mesh-wide (content survived in
    conflicts/, restored by hand).
  - Never land a losing install: a fetch that lost the version race
    while transferring is discarded pre-landing (staging deleted, no
    tree mutation, no quarantine of the winner); a winning local upsert
    aborts a losing in-flight fetch; the superseded-mid-flight revert
    now keeps the identity echo marker through the revert's DELETE
    (a delete-swallow closes it) and RESTORES the quarantined divergent
    copy (the winner's content) instead of leaving a live record with
    no file on disk.
  - T5 now polls for convergence (60s) instead of a fixed 5s sleep — an
    announce-race fetch restart recovered by the stall re-drive takes
    ~17s on the rig.
  - New rig tests: t-ringoverflow.sh (6000-create storm with the daemon
    kill -9'd: ring drops, OVERFLOW marker, rescan convergence, no
    phantom announces), t9-lifecycle.sh (T9 matrix: veto/clean
    unload/M_BRFS freed/replication after reload, N rounds),
    t-overhead.sh (syscall microbench + 13k-file find, loaded vs
    unloaded — tap cost within noise for find/open-close, ~25% on a
    worst-case single-file 20k-write storm, ~4us/op).
  - run_tests.sh now also builds the exe targets: `zig build test` does
    NOT fully analyze them (a broken daemon.zig call site passed green).
  PLUS (promoted 2026-08-24, user): **TLS/mTLS between nodes** — rationale:
  (a) users will run BrFS across the public internet regardless of the
  LAN-only intent; (b) compliance regimes require encryption of all data in
  motion, including LANs/VPNs.  Design constraints: house DANE-first rule
  (TLSA validation primary, local CA trust store fallback, DNSSEC ignored);
  certs from the Pacy World CA (OpenBao-issued); nonblocking-socket TLS via
  OpenSSL/LibreSSL memory-BIO pairs into the existing kqueue core (no
  blocking I/O threads); PSK mode kept as a config fallback for air-gapped
  rigs.  Also: WAN/chaos test track (see test matrix).
- Phase 3 (deferred): durable per-volume journal (biggest DFSR-parity item),
  RDC deltas (>64KB, cross-file seeds), rate limiting/credits + fetch
  pipelining windows (receiver-driven pull is RTT-serialized: ~1 MiB per
  RTT per file — ~20 MB/s ceiling at a 50 ms cross-region RTT, fine for
  POC), node add/remove, >3 nodes, resync skip-on-(size,sha),
  upstreamable registration API if patch fallback used.

## Test matrix (T1–T11)

T1 create, T2 modify, T3 delete, T4 nested dirs, T5 concurrent same-file
(LWW, no partials/storm), T6 resync after 100 offline changes, T7 no-echo,
T8 kill -9 mid-FETCH, T9 kmod load→T1–T8→unload→reload, T10 rename pairs
converge (no delete+create artifacts), T11 event fidelity vs dtrace oracle +
ring overflow→rescan. All repeated with mid-test daemon restarts.
Out of POC scope: deltas, durable journal, sync mode, auth beyond PSK,
ACL/symlink/device propagation, >3 nodes, WAN.

### WAN / chaos track (added 2026-08-24, user)

The deployment target is cross-region WAN: three regions (FL/NY/SD,
10.7.7/8/6.0/24) interconnected by IPsec tunnels through OPNsense — tens of
ms of RTT, occasional loss, tunnel MTU quirks.  Once the engine matures
(post-Phase 2), add a degradation matrix on the rig using FreeBSD's
netgraph — `ng_netem(4)` inserted on the guest vtnet path (or dummynet
pipes scoped to peer-pair traffic as the firewall-touching alternative;
console access via vmctl-brfs is the lockout fallback):

- T21 latency: 25/50/100 ms added per link — convergence must hold,
  fetch timeouts must not false-fire (stall detector, not deadline).
- T22 loss: 0.5%/2% packet drop — TCP hides it, watch for pathological
  re-fetch loops (hash-mismatch requeue is bounded; verify).
- T23 bandwidth cap: 10/1 Mbps — wbuf saturation drops the conn and
  resync heals; no livelock (backoff + dial suppression).
- T24 partition: ngctl shutdown a link for N minutes of writes, heal —
  full convergence via RESYNC (already the T6 mechanism, at WAN scale).

## Packaging (after POC)

net/brfs in deluxe tree (sysutils fallback). PR #239 conventions:
MAINTAINER=daniel@morante.net; files/brfsd.in %%PREFIX%% via USE_RC_SUBR;
@sample under ETCDIR; USES=kmod uidfix zig:0NN; pkg-plist+PLIST_FILES
coexist for ${KMODDIR}; BATCH=yes; kmod pkg needs SRC_BASE in europa
poudriere jails (open item). Local battery before europa:
makesum/stage-qa/check-orphans/package, DEVELOPER=yes; Jenkins
overlay-update→bulk after local green.

## P0.1 findings (2026-08-23, source walk on 15.x /usr/src + host empirical run) — GO

Event taxonomy (all from VOP dispatch-layer post-hooks in vfs_subr.c /
vfs_vnops.c — filesystem-agnostic by construction):
- open → IN_OPEN; read/sendfile → IN_ACCESS; write/extend → IN_MODIFY;
  close → IN_CLOSE_WRITE / IN_CLOSE_NOWRITE
- create/mknod/mkdir/symlink/link → IN_CREATE (INOTIFY_NAME with dvp+cnp)
- unlink/rmdir → IN_DELETE + _IN_ATTRIB_LINKCOUNT (surfaces as IN_ATTRIB)
- rename → IN_MOVED_FROM/IN_MOVED_TO sharing a cookie from the global
  atomic inotify_rename_cookie (confirmed live on 15.0 host:
  `mv` emits the pair; `touch` = CREATE+OPEN+CLOSE_WRITE; `chmod` = ATTRIB;
  `rm` = DELETE; `mkdir` = CREATE)
- chmod/chown/utimes/truncate → IN_ATTRIB; revoke → INOTIFY_REVOKE path
- No recursion, as documented: `touch watched/subdir/nested` after watching
  only `watched` emits nothing — per-directory watches. The kmod's whole-tree
  flagging is what fixes this.

Flag machinery (the load-bearing details for the tap):
- vn_inotify_add_watch sets VIRF_INOTIFY on the watched vnode and walks
  existing dirents setting VIRF_INOTIFY_PARENT on each child
  (vfs_inotify.c:780-818); NEW children are flagged lazily at cache_enter
  (vfs_cache.c:2638) — that path only checks dvp's VIRF_INOTIFY and does not
  care who set it, so our own flagging propagates to new files for free.
- DECAY HAZARD: cache_vop_inotify (vfs_cache.c:4097-4102) UNSETS
  VIRF_INOTIFY_PARENT when no genuinely-watched parent is found. Avoided by
  the tap never forwarding to vop_stdinotify unless the vnode has real
  inotify watches (vp->v_pollinfo->vpi_inotify non-empty — both fields are
  in public struct vnode / vnode.h).
- Exported symbols a kmod can use: vn_irflag_set_cond, cache_vop_inotify,
  vop_stdinotify, inotify_log (all in vnode.h). struct inotify_softc is
  opaque (vfs_inotify.c-private) → no kernel-side inotify watch; not needed.
- nullfs: vn_inotify_add_watch notes the vnode may differ when nullfs is in
  the picture (vfs_inotify.c:821); our ADDROOT namei resolves in the
  caller's namespace to the operative vnode — jail/nullfs model holds.

Refined tap design for P0.2 (supersedes the earlier option list):
- Interpose vop_inotify on the UFS/ZFS vop vectors (enumerate all relevant
  vectors in the spike: file/dir/fifo). Fast path: zero registered roots →
  call original immediately.
- Handler: lineage-check (vp/dvp) against registered roots via namecache
  parent walk (same pattern as cache_vop_inotify) → brfs_emit() to ring.
  Forward to vop_stdinotify ONLY when real inotify watches exist on the
  vnode (preserves inotify compat; sidesteps the decay path).
- BRFSIOC_ADDROOT: namei in caller context (jail-correct), vref the root,
  vn_irflag_set_cond(root, VIRF_INOTIFY), dirent walk setting
  VIRF_INOTIFY_PARENT on existing children (mirror of vfs_inotify.c:780).
  New children propagate via cache_enter. Open spike question: root-dir
  removal/revoke handling while vref'd (vrele on DELROOT/unload; document
  behavior if the tree root is rmdir'd mid-watch).
- GO decision: mechanism is fully mapped with exported symbols; proceed to
  P0.2 implementation in the bhyve rig.

## P0.2 findings (2026-08-24, brfs-a/b/c bhyve rig, 15.1) — GO

The tap is implemented and validated. brfs.ko interposes vop_inotify on
the vop vectors serving registered trees and feeds /dev/brfs; brfsd
drains real filesystem events end-to-end.

Implementation decisions (settled by the spike):

- **Vector patching, lazy and vnode-driven** (supersedes "enumerate the
  vectors"): vfs_vector_op_register() BAKES defaults into each vector at
  registration, so patching default_vnodeops would be useless. Instead
  ADDROOT patches the vop_inotify slot of every vector encountered in
  the tree walk, discovered via vnode->v_op — no symbol references, so
  base-kernel UFS/FFS and module ZFS work identically with no
  MODULE_DEPEND. Only slots holding vop_stdinotify are replaced (bypass
  vectors like nullfs are skipped — their writes reach us via bypass
  re-dispatch on the lower vnode). Restore at DELROOT refcount-zero and
  MOD_UNLOAD. (#14 KBI: single-interposer enforced by the
  == vop_stdinotify precondition; we never stomp a foreign override.)
- **Emit-all** (#13, decided): NO lineage filtering in kernel. The VIRF
  gate flags scope the stream; the daemon discards events outside its
  roots by (fsid, dir_fileid). No namecache walk on the event path, no
  UAF surface. Validated: genuine inotify consumers' events simply pass
  through the same ring.
- **fileid/gen via guarded VOP_GETATTR in the tap**: all vfs_subr.c
  post-hook call sites hold the subject/parent locked EXCEPT the rename
  post hook (args are WILLRELE, already unlocked) — for that one the tap
  takes LK_SHARED|LK_NOWAIT and degrades to fileid=0 (daemon rescans) on
  contention or doom. No vnode locks are ever acquired without NOWAIT.
- **Recursion engine**: VIRF_INOTIFY on every directory (named child
  events are gated on the parent dir's VIRF_INOTIFY), VIRF_INOTIFY_PARENT
  on files (self events). Existing tree flagged by the ADDROOT walk
  (vfs_inotify.c dirent-walk pattern, recursive, iterative queue — no
  kernel stack recursion); new children propagate via cache_enter for
  free; new dirs upgraded by the tap at CREATE; populated dirs renamed
  INTO a tree get a deferred taskqueue subtree walk (preallocated pool —
  no allocation on the event path). The walk trigger must NOT key on
  "was already flagged": the MOVE_FROM half of a rename performs the
  upgrade before MOVE_TO is seen — walk on every MOVE_TO of a dir
  (in-tree moves degenerate to one readdir).
- **Pollinfo invariant (the hard-won one)**: inotify_log() dereferences
  vp->v_pollinfo with NO NULL check — genuine inotify only flags watched
  vnodes, which always have pollinfo. We allocate pollinfo
  (v_addpollinfo) BEFORE setting VIRF_INOTIFY on any directory. Without
  this, the first P0.2 run panicked (page fault in inotify_log from
  cache_vop_inotify, write to 0x18): stale tree flags survived a
  kldunload, the restored vector routed an open(2) on a flagged dir
  straight into vop_stdinotify, NULL pollinfo deref. DELROOT and
  MOD_UNLOAD now also strip directory flags via an unflag walk BEFORE
  vector restore; file PARENT flags self-heal via the genuine decay
  path. Panic regression test (unload with flagged tree, then fts-based
  rm -rf) now passes clean.
- **Forwarding guard**: events reach vop_stdinotify only when genuine
  inotify watches exist on vp/dvp (vpi_inotify non-empty) — otherwise
  vn_inotify's cache_vop_inotify fallback would strip our PARENT flags
  (decay hazard from P0.1, confirmed live: see below).
- **Root-dir rmdir/revoke while vref'd (P0.1 open question, ANSWERED)**:
  the vref pins the doomed vnode; a DELETE event for the root itself
  still fires (named gate on the subject's own VIRF_INOTIFY) so the
  daemon learns the tree died; ops via surviving open fds still fire and
  are safe (pollinfo invariant + emit-all); DELROOT skips the unflag
  walk for doomed roots (cannot readdir), residue is inert after vector
  restore and fades with vnode recycling; re-ADDROOT of the same path
  re-resolves to the new vnode and re-flags. No deadlock, no leak beyond
  transient flags.
- **Consecutive-dedup in the ring**: identical (op, dir_fileid, fileid,
  name) events collapse; a 50-write storm yielded ~12 events (drain
  boundaries). Rename pairs never dedup (op differs). The synthetic
  test_event sysctl uses unique names so it can still fill the ring.
- **Ring overflow**: validated — 5000-event burst into a 4096 ring =
  4096 enqueued + 904 drops, and the next event is preceded by
  BRFS_OP_OVERFLOW (daemon logs "tree rescan required"). Marker seq is
  assigned before the triggering event so ring order stays monotonic.

Validation matrix (all on the 3-VM rig unless noted):

- T11-lite event fidelity: scripted op battery (create/modify/mkdir/
  nested/chmod/rename/delete/import/storm) matches ground truth on
  brfs-a, brfs-b, brfs-c; dir fileids verified against stat(1); va_gen
  disambiguates inode reuse (deleted file vs recreated same-inode file
  carry different gen).
- Oracle coexistence: genuine inotify watcher on the tree received the
  same CREATE/MOVED_FROM/MOVED_TO/DELETE with the SAME rename cookies as
  the brfs feed while brfsd drained concurrently.
- brfsd restart mid-stream: ops performed while the daemon was down
  (including a create inside a directory created during the outage)
  drained intact on restart; seq continuity preserved.
- ZFS: full battery on a file-backed pool passes, including
  same-dataset populated-dir rename-in + deferred walk. (Cross-dataset/
  pool rename is EXDEV — not a case.) NOTE: early ZFS run showed
  spurious pool-wide coverage — root cause was a leftover brfsd from a
  failed attempt still registered on the pool root; single-open guard
  makes overlapping generations confusing in logs. Clean step-by-step
  re-run shows no walk escape and silent gates outside the root.
- Lifecycle: load/unload/reload across repeated rounds, SIGTERM clean
  exit, unload veto while the daemon holds the device (EBUSY), DELROOT
  silence (events stop), reload + re-ADDROOT green.
- Repeatable: tests/vm/tap-smoke.sh runs the battery + lifecycle checks
  and passes on all three VMs.

Known limitations (documented, POC-accepted):

- inotify watch REMOVAL inside our tree strips VIRF_INOTIFY off that dir
  (vfs_inotify.c:377 unsets unconditionally when the last watch goes) —
  coverage for that dir's direct children goes silent until the next
  ADDROOT re-register. inotify is oracle-only for BrFS; the daemon's
  scan layer is the durability floor. RESOLVED 2026-08-25: brfsd
  re-pushes ADDROOT hourly (idempotent re-walk/re-flag); a kernel-side
  refcount is infeasible (inotify_softc opaque, no watch-removal hook).
- Namespace scoping: ADDROOT flags the vnodes resolved in the caller's
  namespace. Writes via a different alias (e.g. host path into a jailed
  nullfs tree) are not covered by the alias registration. Deployment
  rule: the daemon registers the path its writers use.
- Sub-mounts inside a watched tree are not covered (walk does not
  descend; their vectors are not patched).
- First rename after boot carries cookie 0 (inotify_rename_cookie starts
  at 0) — pair by (cookie, op adjacency), 0 is not "no cookie" for
  MOVE_* ops.
- Ring emits no IN_CLOSE_WRITE/IN_ACCESS/IN_OPEN (read-side noise);
  daemon coalescing is the quiescence signal for POC tests.
- ~~The unload grace for in-flight tap calls is pause(hz); a hard
  epoch-style drain is Phase 2 hardening.~~ RESOLVED 2026-08-25: the tap
  runs inside a preemptible epoch section; MOD_UNLOAD does
  epoch_wait_preempt() after vector restore — a hard drain guarantee.
- Guest pkg/DNS through the rig NAT is broken (resolver failures) —
  build oracle/test tools on the host or in-guest from source.

GO: proceed to Phase 1 (brfsd replication logic). The kernel change
feed is proven sufficient; no fallback (kernel patch) was needed.

## Risks

Self-echo loops (rule 6 + T7); kmod UAF (safety bar + T9 + witness/dtrace,
never on host); vop interposition/flag-propagation unknowns (P0.1/P0.2 gate);
kmod on POC critical path (accepted — decision 4); ring overflow (drop flag →
rescan T11); hardlink aliasing (fileid lineage + T11); storage on
freebsd-dev1 (VMs on vault pool).
