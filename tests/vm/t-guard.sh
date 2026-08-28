#!/bin/sh
# t-guard.sh — gap #17 mass-delete guard on the rig.
#
# 200 files converge; a rm -rf on A must trip the guard (tombstones
# suppressed — B/C keep their copies); brfsctl massdelete resume releases
# the latch and the rescan re-derives the deletes, converging the mesh.
#
# usage: sh tests/vm/t-guard.sh
set -u
A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
CTLM=/tmp/brfs-ssh-ctl
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60 -o ControlPath=$CTLM-%h"
N=200
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

note "setup: clean trees, daemons running"
for ip in $A $B $C; do CTL $ip reset; done
for ip in $A $B $C; do CTL $ip start; done
sleep 8
for ip in $A $B $C; do
	CTL $ip started || { fail "brfsd start on $ip"; CTL $ip log 8; }
done

note "seed $N files on A"
R $A "mkdir -p $TREE/g && i=0; while [ \$i -lt $N ]; do echo data-\$i > $TREE/g/f\$i; i=\$((i+1)); done"
i=0
while [ $i -lt 120 ]; do
	nb=$(R $B "ls $TREE/g 2>/dev/null | wc -l" | tr -d ' \r\n')
	nc=$(R $C "ls $TREE/g 2>/dev/null | wc -l" | tr -d ' \r\n')
	[ "$nb" = "$N" ] && [ "$nc" = "$N" ] && break
	sleep 1; i=$((i + 1))
done
[ "$nb" = "$N" ] && [ "$nc" = "$N" ] && ok "seed converged" \
	|| { fail "seed convergence (b=$nb c=$nc)"; }

note "rm -rf on A — guard must latch, B/C must keep their copies"
R $A "rm -rf $TREE/g"
sleep 15
if CTL $A "logcount MASS-DELETE GUARD TRIPPED" | grep -q "^[1-9]"; then
	ok "guard tripped on A"
else
	fail "guard did not trip on A"
	CTL $A log 10
fi
R $A "doas /tmp/brfsctl massdelete" | grep -q "LATCHED" \
	&& ok "ctl massdelete shows LATCHED" || fail "ctl massdelete state"
nb=$(R $B "ls $TREE/g 2>/dev/null | wc -l" | tr -d ' \r\n')
nc=$(R $C "ls $TREE/g 2>/dev/null | wc -l" | tr -d ' \r\n')
# The storm stopped at the latch point; peers must still hold MOST of
# the tree (and strictly more than half — the guard trips at ~50%).
if [ "$nb" -gt $((N / 2)) ] 2>/dev/null && [ "$nc" -gt $((N / 2)) ] 2>/dev/null; then
	ok "peers kept the tree (b=$nb c=$nc of $N)"
else
	fail "tombstone storm leaked (b=$nb c=$nc)"
fi

note "operator release: massdelete resume -> deletes converge"
R $A "doas /tmp/brfsctl massdelete resume"
i=0
b_gone=0; c_gone=0
while [ $i -lt 60 ]; do
	R $B "test -e $TREE/g" || b_gone=1
	R $C "test -e $TREE/g" || c_gone=1
	[ $b_gone -eq 1 ] && [ $c_gone -eq 1 ] && break
	sleep 1; i=$((i + 1))
done
[ $b_gone -eq 1 ] && [ $c_gone -eq 1 ] \
	&& ok "deletes converged after resume" \
	|| fail "deletes did not converge after resume (b_gone=$b_gone c_gone=$c_gone)"
R $A "doas /tmp/brfsctl massdelete" | grep -q "clear" \
	&& ok "guard clear after resume" || fail "guard state after resume"

if [ "$fails" -eq 0 ]; then
	echo "GUARD PASS"
else
	echo "GUARD FAIL ($fails failures)"
	exit 1
fi
