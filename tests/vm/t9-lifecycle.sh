#!/bin/sh
# t9-lifecycle.sh — T9 kmod lifecycle matrix, run on the HOST driving the
# brfs-a/b/c rig: replication smoke -> unload -> reload, repeated.
# Asserts: unload veto while daemon holds /dev/brfs, clean unload after
# daemon stop (no dangling reader), no M_BRFS memory leak across rounds,
# replication green after each reload.
#
# usage: sh tests/vm/t9-lifecycle.sh [rounds]
set -u
A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
CTLM=/tmp/brfs-ssh-ctl
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60 -o ControlPath=$CTLM-%h"
ROUNDS=${1:-3}
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

sha_on() { R "$1" "sha256 -q $2 2>/dev/null" | tr -d ' \r\n'; }

wait_file() { # wait_file <ip> <rel> <want-sha> <timeout-s>
	ip=$1; rel=$2; want=$3; tmo=$4; i=0
	while [ $i -lt $((tmo * 2)) ]; do
		got=$(sha_on "$ip" "$TREE/$rel")
		[ "$got" = "$want" ] && return 0
		sleep 0.5; i=$((i + 1))
	done
	return 1
}

smoke() { # smoke <tag>: create/modify/delete converges from A
	tag=$1
	R $A "echo t9-$tag > $TREE/t9-$tag.txt"
	want=$(sha_on $A $TREE/t9-$tag.txt)
	wait_file $B t9-$tag.txt "$want" 30 && wait_file $C t9-$tag.txt "$want" 30 \
		|| { fail "replication after reload ($tag)"; return 1; }
	R $A "echo more >> $TREE/t9-$tag.txt"
	want=$(sha_on $A $TREE/t9-$tag.txt)
	wait_file $C t9-$tag.txt "$want" 30 || { fail "modify after reload ($tag)"; return 1; }
	R $A "rm $TREE/t9-$tag.txt"
	i=0
	while [ $i -lt 60 ]; do
		R $B "test -e $TREE/t9-$tag.txt" || { R $C "test -e $TREE/t9-$tag.txt" || break; }
		sleep 0.5; i=$((i + 1))
	done
	[ $i -lt 60 ] || { fail "delete after reload ($tag)"; return 1; }
	ok "replication smoke ($tag)"
	return 0
}

mem_on() { # mem_on <ip>: M_BRFS in-use bytes,count line
	R "$1" "vmstat -m | awk '/^brfs/ {print \$2, \$3}'" | tr -d ' \r\n'
}

round=1
while [ $round -le $ROUNDS ]; do
	note "T9 round $round/$ROUNDS"

	# Unload veto: daemon holds /dev/brfs -> kldunload must fail.
	for ip in $A $B $C; do
		R $ip "doas kldunload brfs 2>/dev/null" \
			&& fail "unload not vetoed on $ip (daemon running)" \
			|| true
	done
	ok "unload vetoed while daemons hold /dev/brfs"

	# Clean stop + unload + reload.
	for ip in $A $B $C; do CTL $ip stop; done
	sleep 2
	for ip in $A $B $C; do
		R $ip "doas kldunload brfs" || fail "kldunload on $ip"
	done
	for ip in $A $B $C; do
		m=$(mem_on $ip)
		[ -z "$m" ] || fail "M_BRFS not freed on $ip after unload: $m"
	done
	ok "unload clean, M_BRFS freed"
	for ip in $A $B $C; do
		R $ip "doas kldload /tmp/kmod/brfs.ko" || fail "kldload on $ip"
		CTL $ip start
	done
	sleep 8
	for ip in $A $B $C; do
		CTL $ip started || { fail "brfsd start after reload on $ip"; CTL $ip log 8; }
	done

	smoke "r$round"
	round=$((round + 1))
done

if [ "$fails" -eq 0 ]; then
	echo "T9 PASS ($ROUNDS rounds)"
else
	echo "T9 FAIL ($fails failures)"
	exit 1
fi
