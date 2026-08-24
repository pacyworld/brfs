# BrFS — BSD Replicated File System

A DFSR-style **replicated folder engine** for FreeBSD. An ordinary directory
tree on each node stays replicated to N peers — multi-master, asynchronous,
eventual consistency. Reads are always local and fast; the filesystem is just
a container.

BrFS is **not** a distributed filesystem: no new mount point, no FUSE, no
client-server storage pool, no translator stack (the GlusterFS shape is
explicitly rejected). It is a *service over the VFS*, in the style of Windows
DFS Replication.

## Components

| Component  | Language | Role |
|------------|----------|------|
| `brfs.ko`  | C        | Kernel event tap: hooks the FreeBSD 15 VFS event notification points (`VOP_INOTIFY`), feeds a kernel-owned ring buffer behind `/dev/brfs`. Required; this is the only change feed. |
| `brfsd`    | Zig      | The replication daemon: event consumer, content set, journal (per-path coalescing), peer protocol, staging + atomic-rename installer, conflict quarantine, resync. |
| `brfsctl`  | Zig      | Operator utility: stats, peers, backlog, resync triggers, conflict management. |

## Design decisions (locked)

- **CAP: AP** — multi-master, eventual consistency. No Raft in the data path.
- **Minimum 2 members, no quorum.** Design for N; POC runs 3.
- **Conflicts: last-writer-wins** by `(version, node_id)`; the losing version
  is quarantined to `/var/db/brfs/conflicts/`, never silently dropped.
- **Change feed: `brfs.ko` only.** Native inotify (15.0+) rides the same VFS
  notification points but is a compat ABI, not a replication-grade feed —
  it is used here strictly as a test oracle.
- **Atomic installs only**: staging + `rename(2)`; no reader ever sees a
  partial file.

See [docs/PLAN.md](docs/PLAN.md) for the full design document and
[docs/protocol.md](docs/protocol.md) for the wire protocol.

## Requirements

- FreeBSD 15.0+ (VFS event notification points, rGbc4430dc203e)
- Kernel sources at `/usr/src` to build `brfs.ko`
- Zig 0.15.x to build `brfsd`/`brfsctl`

## Building

```sh
make -C kmod          # builds kmod/brfs.ko
zig build             # builds brfsd and brfsctl into zig-out/bin/
zig build test        # unit tests
```

## Status

Phase 0 (spikes). See the test matrix in docs/PLAN.md.
