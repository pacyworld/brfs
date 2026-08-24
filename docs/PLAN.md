# BrFS (BSD Replicated File System) — DFSR-style Replicated Folder Engine for FreeBSD

Status: PLANNING → IMPLEMENTATION (v0.4, 2026-08-23)
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
  path), contentset.zig ({id, ver, size, mtime, sha256}; POC append-only +
  snapshot, checksummed, corrupt→rebuild-via-scan; LMDB/SQLite later),
  journal.zig (per-path coalescing), protocol.zig (mutation-tested codec,
  securemilter-lib pattern), peer.zig/server.zig (full mesh,
  retries/backoff, PSK-in-HELLO POC, TLS later), installer.zig (staging +
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

- Phase 0 spikes: P0.0 DONE; P0.1 characterize notification points (source +
  dtrace + inotify-tools oracle: event taxonomy, rename cookies,
  VIRF_INOTIFY_PARENT propagation, NFS/nullfs coverage, flag lifecycle on
  vnode recycle); P0.2 GATING kmod spike (tap + flags + ring + /dev/brfs,
  GO/NO-GO, NO-GO→kernel-patch strategy); P0.3 bhyve 3×VM rig on vault pool
  (vmctl pattern: UEFI BHYVE_UEFI.fd, nmdm serial, ttyu0 getty OFF,
  bridge+tap+NAT via pf cni-nat; zig NOT in guest — host builds, scp; kmod
  builds in-guest; NEVER test kmod on host); P0.4 repo scaffolding.
- Phase 1: POC end-to-end ON brfs.ko from day one. T1–T8 green on 3 VMs with
  mid-test daemon restarts.
- Phase 2: kernel hardening — fidelity vs dtrace oracle, ring sizing/drop
  behavior, overhead measurement, T9 matrix, unload veto while fd held.
- Phase 3 (deferred): durable per-volume journal (biggest DFSR-parity item),
  RDC deltas (>64KB, cross-file seeds), rate limiting/credits, TLS/mTLS
  (vault-issued), node add/remove, >3 nodes, resync skip-on-(size,sha),
  upstreamable registration API if patch fallback used.

## Test matrix (T1–T11)

T1 create, T2 modify, T3 delete, T4 nested dirs, T5 concurrent same-file
(LWW, no partials/storm), T6 resync after 100 offline changes, T7 no-echo,
T8 kill -9 mid-FETCH, T9 kmod load→T1–T8→unload→reload, T10 rename pairs
converge (no delete+create artifacts), T11 event fidelity vs dtrace oracle +
ring overflow→rescan. All repeated with mid-test daemon restarts.
Out of POC scope: deltas, durable journal, sync mode, auth beyond PSK,
ACL/symlink/device propagation, >3 nodes, WAN.

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

## Risks

Self-echo loops (rule 6 + T7); kmod UAF (safety bar + T9 + witness/dtrace,
never on host); vop interposition/flag-propagation unknowns (P0.1/P0.2 gate);
kmod on POC critical path (accepted — decision 4); ring overflow (drop flag →
rescan T11); hardlink aliasing (fileid lineage + T11); storage on
freebsd-dev1 (VMs on vault pool).
