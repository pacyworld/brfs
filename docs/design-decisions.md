# BrFS design decisions — review-mandated writeups

This document carries the written rationale the code review
(`BrFS Code Review — scaffold @19de9e2`) required for items that are
DECISIONS rather than code. Each section names its review/gap item.

## Gap #14 — KBI stability of the VOP_INOTIFY interposition

**Constraint.** `struct vop_vector` is not a stable KBI across FreeBSD
15.x point releases, and our tap works by interposing the `vop_inotify`
slot of the target filesystems' vectors at runtime. Two hazards follow:

1. *Layout drift*: a point release could in principle add a vector entry
   and shift slots. Mitigation: brfs.ko is built from source against the
   running kernel's `/usr/src` (the port uses `USES=kmod`; there is no
   binary distribution across kernel versions), so a drifted layout is a
   rebuild, not a runtime surprise.
2. *Competing interposers*: save/restore on load/unload assumes we are
   the only interposer. If another module (or a future inotify-aware
   agent) replaced `vop_inotify` after us, our unload would restore a
   stale pointer and corrupt the chain.

**Runtime assertion (enforced, P0.2).** At patch time each candidate
vector's `vop_inotify` slot MUST equal `vop_stdinotify`:

- equal → we patch it, record `(vec, orig)` in `brfs_vecs`, refcount per
  additional root;
- not equal → the vector is LEFT ALONE (foreign override or bypass) and
  the event is logged; we never stack on top of another interposer.

Unload restores each recorded original exactly once, in reverse
attribution order, after an epoch drain (`epoch_wait_preempt`) of the tap
— a thread mid-tap either sees the old or the new pointer, both valid
(single aligned pointer store; readers never sleep holding the tap).

**Single-interposer rule (documented constraint).** brfs.ko MUST be the
only module interposing `vop_inotify`. This is enforceable today because
the only known consumers of the notification points are inotify itself
(`vop_stdinotify`) and BrFS. If a second interposer ever appears, the
correct resolution is a kernel-side registration API (upstreamable), NOT
pointer stacking.

## Gap #15 — why the MAC framework was rejected as the event tap

The MAC framework (we ship prior art: `mac_do_auto`) is a *supported* KPI,
so it was seriously considered. Rejected because its semantics are the
wrong shape for a change feed:

- **Pre-op, not post-op.** MAC vnode hooks (`mac_vnode_check_*`) run
  BEFORE the operation and answer "allow/deny". A replication feed needs
  "this happened, and here is the result". Denying is never our intent;
  observing is. Hooking pre-op checks means reporting events for
  operations that may still fail (EPERM from a later check, I/O error,
  quota) — phantom changes the mesh would have to un-toast.
- **No rename pairing.** The inotify notification points carry a rename
  cookie pairing MOVED_FROM/MOVED_TO (`inotify_rename_cookie`). MAC's
  `mac_vnode_check_rename_from/to` carry no shared token; reconstructing
  rename pairs across concurrent renames would require exactly the kind
  of speculative correlation state the kmod is forbidden to hold.
- **Policy iteration cost.** MAC hooks run through the policy list on
  EVERY vnode operation system-wide once a policy registers interest;
  our flag-gated tap is a single predictable-false branch on untouched
  trees and a direct call on watched ones.
- **Namespace/delivery mismatch.** A MAC policy still needs a delivery
  channel to userland; we would end up re-implementing the cdev + ring +
  ioctl surface anyway, with zero gain over tapping the notification
  points that exist precisely for observation.

Decision stands: `vop_inotify` interposition with flag gating. The MAC
framework remains the right answer for *policy* (who may register roots:
`PRIV_DRIVER` + `/dev/brfs` 0600), which is how we use it implicitly via
the cdev permission checks.

## Gap #11 — per-root drop flags: why the filter is daemon-side

The kmod tap is emit-all BY DECISION (review item #13): per-event lineage
attribution ("which registered root does this vnode belong to") is a
namecache walk on the kernel hot path with a lock-order/UAF surface we
deliberately do not own. The VIRF gate flags scope the stream to watched
trees; the daemon resolves `fsid/fileid` → path through its identity
index and applies policy there.

Consequences:

- Ring overflow handling is a full rescan (admitted, rig-proven in
  `t-ringoverflow.sh`), not a per-root targeted one: the kmod cannot
  attribute a dropped event to a root it never resolved.
- Selective event filtering IS available, at the only place lineage is
  known: the daemon. `events_drop = ["attrib", ...]` in brfs.conf drops
  op classes at intake (dropped classes are recovered by the scan floor,
  not in real time). `overflow` is never droppable.
- The `br_mask` field in `struct brfs_root` (ABI) is reserved and
  currently unused; a future kernel-side use must not reintroduce
  hot-path lineage walks.

## Gap #16 — forced unmount of the watched filesystem

**kmod side.** A registered root holds a `vref`'d vnode, so a normal
`umount` of a watched filesystem fails `EBUSY` — unwatch first (DELROOT)
or stop brfsd. `umount -f` overrides: the mount's vnodes are doomed,
flag state dies with them, and the tap's doomed-subject checks
(`VN_IS_DOOMED`) keep the event path safe. No kernel change is needed;
unload with a doomed root vref is clean (`vrele` on a doomed vnode is
valid).

**The dangerous half is the daemon.** After `umount -f`, the watched
path resolves to the bare mountpoint directory on the PARENT filesystem:
the tree looks empty, and the scan floor would tombstone every record —
a self-inflicted mesh-wide annihilation (the same failure class the
gap #17 mass-delete guard covers). Defense (rig-proven by
`tests/vm/t-unmount.sh` on a scratch ZFS dataset):

- *Runtime (daemon up, fs unmounted under it):* every rescan-floor pass
  and the hourly watch-root re-push re-check the root's `f_fsid`; a
  mismatch defers scans with an error log and suppresses the re-push
  (which would flag the parent fs's tree). No tombstones are issued.
  ZFS fsids are mount-stable (verified empirically on the rig: the
  dataset's `f_fsid` is identical before and after unmount/mount), so a
  remount restores the match and the next scan converges automatically.
- *Startup with the fs still down:* the canonical layout puts state_dir
  on the SAME filesystem as the tree (the staging rename rule), so the
  tree path simply does not resolve — `BRFSIOC_ADDROOT` fails and brfsd
  exits fatally before any state is touched. Fail-fast, no storm.
- *Fs legitimately rebuilt (new fsid) or restored from backup:* the
  content set stamps the root's fsid in LMDB meta on first start; a
  mismatch at open freezes replication (watch un-registered, scans and
  local announces stopped, `fs: FROZEN` in `brfsctl status`) until the
  operator wipes `state_dir` and reseeds — the deliberate choice beats a
  silent full re-announce.

**Jails.** brfs.ko loads on the host kernel; a jailed brfsd consumes
`/dev/brfs` via the jail's devfs ruleset — sample in
`etc/devfs.rules.sample`. Registration is namespace-clean (the ioctl path
resolves in the caller's namespace and the kmod filters by fileid
lineage), so a jail can only watch subtrees it can itself resolve.
