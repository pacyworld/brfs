#!/bin/sh
# t-overhead.sh — kmod overhead measurement (mac_do_auto method), run on
# the HOST against brfs-a: syscall microbench (open/read/close and
# append-write loops) + 13k-file find(1), with brfs.ko unloaded vs
# loaded+watching.  The tap's event-path cost must stay in the noise.
#
# usage: sh tests/vm/t-overhead.sh
set -u
A=10.66.0.11
CTLM=/tmp/brfs-ssh-ctl
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60 -o ControlPath=$CTLM-$A"
BENCH=/data/bench
NFILES=13000   # 130 dirs x 100 files
NOPS=20000     # microbench iterations

ssh -MNf -o BatchMode=yes -o ConnectTimeout=60 \
	-o ControlPath=$CTLM-$A -o ControlPersist=30m admin@$A 2>/dev/null || true
trap 'ssh -O exit -o ControlPath=$CTLM-$A admin@$A 2>/dev/null' EXIT

note() { echo "== $*"; }

# Guest-side bench driver (avoids nested quoting): builds bench.c if
# needed, creates the tree if missing, then runs one arm.
$SSH admin@$A "doas sh -c 'pkill -x brfsd 2>/dev/null; kldunload brfs 2>/dev/null; true'"

note "setup: bench tool + $NFILES-file tree (kmod unloaded)"
scp -o BatchMode=yes -o ControlPath=$CTLM-$A \
	"$(dirname "$0")/bench.c" admin@$A:/tmp/bench.c
$SSH admin@$A "cc -O2 -o /tmp/bench /tmp/bench.c"
$SSH admin@$A "test -d $BENCH/d129 && exit 0; doas mkdir -p $BENCH && doas chown admin $BENCH; i=0; while [ \$i -lt 130 ]; do mkdir $BENCH/d\$i; j=0; while [ \$j -lt 100 ]; do echo seed > $BENCH/d\$i/f\$j; j=\$((j+1)); done; i=\$((i+1)); done"
$SSH admin@$A "test \$(find $BENCH -type f | wc -l | tr -d ' ') -ge $NFILES" \
	|| { echo "FAIL: tree setup"; exit 1; }

run_arm() { # run_arm <label>; prints find/bench times
	label=$1
	find_t=$($SSH admin@$A "doas sh -c 'sync; t0=\$(date +%s%N); find $BENCH -type f > /dev/null; t1=\$(date +%s%N); echo \$(( (t1-t0)/1000000 ))'")
	bench=$($SSH admin@$A "/tmp/bench $BENCH/d0/f0 $NOPS")
	oc=$(echo "$bench" | awk '{print $2}')
	wr=$(echo "$bench" | awk '{print $4}')
	echo "$label: find=${find_t}ms openclose=${oc}s/${NOPS} write=${wr}s/${NOPS}"
}

note "arm 0: kmod unloaded"
run_arm "unloaded"

note "arm 1: kmod loaded + watching"
$SSH admin@$A "doas sh -c 'kldload /tmp/kmod/brfs.ko && /tmp/brfs-devtest add $BENCH && /tmp/brfs-devtest add /data/replicated'"
run_arm "loaded+watching"

note "teardown"
$SSH admin@$A "doas sh -c '/tmp/brfs-devtest del $BENCH; /tmp/brfs-devtest del /data/replicated; kldunload brfs; kldload /tmp/kmod/brfs.ko'"
echo "OVERHEAD DONE (compare arms; tap cost should be within a few %)"
