#!/bin/sh
# t-ringoverflow.sh — ring drop behavior + overflow-triggered rescan
# convergence, run on the HOST driving the brfs-a/b/c rig.
#
# With all daemons stopped, create NFILES > ring capacity (4096) on A so
# the kernel ring drops and the in-band BRFS_OP_OVERFLOW marker lands.
# Restarting the daemons must log the overflow, rescan, and converge B/C.
#
# usage: sh tests/vm/t-ringoverflow.sh [nfiles]
set -u
A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
CTLM=/tmp/brfs-ssh-ctl
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60 -o ControlPath=$CTLM-%h"
NFILES=${1:-6000}
fails=0

for ip in $A $B $C; do
	ssh -MNf -o BatchMode=yes -o ConnectTimeout=60 \
		-o ControlPath=$CTLM-$ip -o ControlPersist=30m admin@$ip 2>/dev/null || true
done
trap 'for ip in $A $B $C; do ssh -O exit -o ControlPath=$CTLM-$ip admin@$ip 2>/dev/null; done' EXIT

note() { echo "== $*"; }
ok()   { echo "ok: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }

R()   { $SSH admin@"$1" "$2"; }
CTL() { $SSH admin@"$1" "sh /tmp/brfs-node-ctl.sh $2"; }

note "setup: clean trees, daemons running (roots registered)"
for ip in $A $B $C; do CTL $ip reset; done
for ip in $A $B $C; do CTL $ip start; done
sleep 8
for ip in $A $B $C; do
	CTL $ip started || { fail "brfsd start on $ip"; CTL $ip log 8; }
done

# kill -9 A's daemon: no DELROOT at exit, so the tree stays flagged and
# the ring keeps accumulating with no consumer.  (A clean stop would
# unregister the root and the storm would emit nothing.)
CTL $A kill9
sleep 1
# The whole premise is "no consumer": verify the kill actually landed
# (a missed kill leaves a draining daemon and the ring never overflows).
if R $A "pgrep -x brfsd >/dev/null"; then
	fail "kill -9 left brfsd running on A"
else
	ok "A's daemon confirmed dead"
fi

note "storm: $NFILES creates on A with its daemon dead"
R $A "mkdir -p $TREE/of && i=0; while [ \$i -lt $NFILES ]; do echo data-\$i > $TREE/of/f\$i; i=\$((i+1)); done"

drops=$(R $A "sysctl -n security.brfs.ring_drops" | tr -d ' \r\n')
count=$(R $A "sysctl -n security.brfs.event_count" | tr -d ' \r\n')
echo "  kmod: event_count=$count ring_drops=$drops (ring capacity 4096)"
[ "$drops" -gt 0 ] 2>/dev/null || fail "ring drops not recorded"
[ "$drops" -gt 0 ] 2>/dev/null && ok "ring dropped under storm (drops=$drops)"

note "restart A; expect overflow rescan + convergence"
CTL $A start
sleep 8
CTL $A started || { fail "brfsd restart on A"; CTL $A log 8; }

# A must have seen the overflow marker and run the rescan.
if CTL $A logcount "ring overflow" | grep -q "^[1-9]"; then
	ok "A logged ring overflow"
else
	fail "A never saw the overflow marker"
	CTL $A log 15
fi

# Convergence: file count on B and C must reach NFILES.
i=0
while [ $i -lt 600 ]; do
	nb=$(R $B "ls $TREE/of 2>/dev/null | wc -l" | tr -d ' \r\n')
	nc=$(R $C "ls $TREE/of 2>/dev/null | wc -l" | tr -d ' \r\n')
	[ "$nb" = "$NFILES" ] && [ "$nc" = "$NFILES" ] && break
	sleep 1; i=$((i + 1))
done
echo "  after ${i}s: B=$nb C=$nc (want $NFILES)"
[ "$nb" = "$NFILES" ] && [ "$nc" = "$NFILES" ] \
	&& ok "overflow rescan converged ($NFILES files)" \
	|| fail "convergence after ring overflow"

# Spot-check content integrity of a few files.
want=$(R $A "sha256 -q $TREE/of/f42 $TREE/of/f5999 2>/dev/null" | tr -d ' \r\n')
got=$(R $C "sha256 -q $TREE/of/f42 $TREE/of/f5999 2>/dev/null" | tr -d ' \r\n')
[ -n "$want" ] && [ "$want" = "$got" ] && ok "content spot-check" \
	|| fail "content mismatch after overflow convergence"

if [ "$fails" -eq 0 ]; then
	echo "RING-OVERFLOW PASS"
else
	echo "RING-OVERFLOW FAIL ($fails failures)"
	exit 1
fi
