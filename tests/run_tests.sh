#!/bin/sh
# BrFS test harness. Currently: host-side build + unit tests.
# The T1-T11 cluster matrix runs inside the bhyve test rig (Phase 0 P0.3):
#
#   T1  create propagates            T7  no self-echo loops
#   T2  modify propagates            T8  kill -9 mid-FETCH safety
#   T3  delete propagates            T9  kmod load/unload/reload lifecycle
#   T4  nested dirs propagate        T10 rename pairs converge
#   T5  concurrent same-file LWW     T11 event fidelity vs dtrace oracle
#   T6  resync after offline changes     + ring overflow -> rescan
#
# All cluster tests run repeatedly with the daemon restarted mid-test.

set -eu

cd "$(dirname "$0")/.."

echo "==> zig build test"
zig build test

# zig build test does NOT fully analyze the exe targets (a daemon.zig
# callsite error slipped through 2026-08-26): build the binaries too.
echo "==> zig build (brfsd + brfsctl)"
zig build

echo "==> kmod build"
make -C kmod >/dev/null
test -f kmod/brfs.ko
echo "kmod/brfs.ko built"

echo "OK"
