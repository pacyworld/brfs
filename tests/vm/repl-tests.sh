#!/bin/sh
# repl-tests.sh — Phase 1 replication test matrix (T1-T8, T10), run on the
# HOST (freebsd-dev1) driving the brfs-a/b/c bhyve rig over ssh.
#
# Expects per node: /tmp/brfsd, /tmp/brfs.conf, /tmp/brfs.psk,
# /tmp/brfs-node-ctl.sh (guest-side helper, from tests/vm/), brfs.ko
# loaded, admin ssh + doas nopass.  Daemons run as root via doas because
# /dev/brfs is a root cdev in POC.
#
#   T1 create propagates            T7  no self-echo loops
#   T2 modify propagates            T8  kill -9 mid-FETCH safety
#   T3 delete propagates            T10 rename pairs converge
#   T4 nested dirs propagate            (no delete+create artifacts)
#   T5 concurrent same-file LWW
#   T6 resync after 100 offline changes
#
# T2 includes a mid-test daemon restart on a replica node.
#
# usage: sh tests/vm/repl-tests.sh
set -u

A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
CTLM=/tmp/brfs-ssh-ctl
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60 -o ControlPath=$CTLM-%h"
fails=0

# Connection reuse: the guest sshd banner delay makes per-call handshakes
# dominate the wall clock otherwise.
for ip in $A $B $C; do
	ssh -MNf -o BatchMode=yes -o ConnectTimeout=60 \
		-o ControlPath=$CTLM-$ip -o ControlPersist=30m admin@$ip
done
trap 'for ip in $A $B $C; do ssh -O exit -o ControlPath=$CTLM-$ip admin@$ip 2>/dev/null; done' EXIT

note() { echo "== $*"; }
ok()   { echo "ok: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }

R() { # R <ip> <cmd>  (admin; tree ops)
	$SSH admin@"$1" "$2"
}

CTL() { # CTL <ip> <subcommand...>
	$SSH admin@"$1" "sh /tmp/brfs-node-ctl.sh $2"
}

sha_on() { # sha_on <ip> <abspath> -> sha or empty
	R "$1" "sha256 -q $2 2>/dev/null" | tr -d ' \r\n'
}

wait_file() { # wait_file <ip> <rel> <want-sha> <timeout-s>
	ip=$1; rel=$2; want=$3; tmo=$4; i=0
	while [ $i -lt $((tmo * 2)) ]; do
		got=$(sha_on "$ip" "$TREE/$rel")
		[ "$got" = "$want" ] && return 0
		sleep 0.5; i=$((i + 1))
	done
	echo "  (timeout waiting for $rel on $ip: want=$want got=$got)"
	return 1
}

wait_absent() { # wait_absent <ip> <rel> <timeout-s>
	ip=$1; rel=$2; tmo=$3; i=0
	while [ $i -lt $((tmo * 2)) ]; do
		R "$ip" "test -e $TREE/$rel" || return 0
		sleep 0.5; i=$((i + 1))
	done
	return 1
}

reset_all() {
	note "reset: stop daemons, wipe trees + state, restart"
	for ip in $A $B $C; do CTL "$ip" reset; done
	for ip in $A $B $C; do CTL "$ip" start; done
	sleep 8
	for ip in $A $B $C; do
		CTL "$ip" started || { fail "brfsd start on $ip"; CTL "$ip" log 8; }
	done
}

# ---------------------------------------------------------------- setup
reset_all

# ------------------------------------------------------------------ T1
note "T1 create propagates"
R $A "echo t1-content > $TREE/t1.txt"
want=$(sha_on $A $TREE/t1.txt)
wait_file $B t1.txt "$want" 30 && wait_file $C t1.txt "$want" 30 \
	&& ok "T1" || fail "T1 create"

# ------------------------------------------------------------------ T2
note "T2 modify propagates (with mid-test restart of b)"
CTL $B stop
R $A "echo t2-more >> $TREE/t1.txt"
CTL $B start
want=$(sha_on $A $TREE/t1.txt)
wait_file $B t1.txt "$want" 30 && wait_file $C t1.txt "$want" 30 \
	&& ok "T2" || fail "T2 modify"

# ------------------------------------------------------------------ T3
note "T3 delete propagates"
R $A "rm $TREE/t1.txt"
wait_absent $B t1.txt 30 && wait_absent $C t1.txt 30 \
	&& ok "T3" || fail "T3 delete"

# ------------------------------------------------------------------ T4
note "T4 nested dirs propagate"
R $A "mkdir -p $TREE/x/y/z && echo deep > $TREE/x/y/z/deep.txt && echo mid > $TREE/x/mid.txt"
want=$(sha_on $A $TREE/x/y/z/deep.txt)
wait_file $C x/y/z/deep.txt "$want" 30 || fail "T4 deep file"
want2=$(sha_on $A $TREE/x/mid.txt)
wait_file $B x/mid.txt "$want2" 30 && ok "T4" || fail "T4 nested"

# ------------------------------------------------------------------ T5
note "T5 concurrent same-file writes converge (LWW)"
R $B "echo content-from-b > $TREE/race.txt" & pb=$!
R $C "echo content-from-c > $TREE/race.txt" & pc=$!
rb=0; rc=0; wait $pb || rb=$?; wait $pc || rc=$?
if [ $rb -ne 0 ] || [ $rc -ne 0 ]; then
	fail "T5 write side failed (b=$rb c=$rc) — tree not admin-writable?"
else
# Poll for convergence: an announce race can restart a fetch mid-flight,
# and the stall detector's re-drive legitimately exceeds a fixed 5s sleep
# (rig-proven: fetch-swap on a flapping conn recovered at ~17s).
i=0
while [ $i -lt 60 ]; do
	sa=$(sha_on $A $TREE/race.txt); sb=$(sha_on $B $TREE/race.txt); sc=$(sha_on $C $TREE/race.txt)
	[ -n "$sa" ] && [ "$sa" = "$sb" ] && [ "$sa" = "$sc" ] && break
	sleep 1; i=$((i + 1))
done
if [ -n "$sa" ] && [ "$sa" = "$sb" ] && [ "$sa" = "$sc" ]; then
	ok "T5 converged (all = $sa, ${i}s)"
else
	fail "T5 divergence: a=$sa b=$sb c=$sc"
fi
fi

# ------------------------------------------------------------------ T6
note "T6 resync after 100 offline changes"
CTL $C stop
i=0; while [ $i -lt 100 ]; do R $A "echo v$i > $TREE/off$i.txt"; i=$((i + 1)); done
CTL $C start
sleep 3
last=$(sha_on $A $TREE/off99.txt)
if wait_file $C off99.txt "$last" 90; then
	got=$(R $C "ls $TREE | grep -c '^off[0-9]*\.txt$'")
	[ "$got" = "100" ] && ok "T6" || fail "T6 count=$got"
else
	fail "T6 resync"
fi

# ------------------------------------------------------------------ T7
note "T7 no self-echo loops"
R $A "echo t7 > $TREE/t7.txt"
sleep 5
# Originator lines contain ": announce t7.txt v=..."; receiver trace lines
# contain ": recv announce ..." — the fixed-string form excludes receivers.
na=$(CTL $A "logcount : announce t7.txt")
nb=$(CTL $B "logcount : announce t7.txt")
nc=$(CTL $C "logcount : announce t7.txt")
if [ "$na" = "1" ] && [ "$nb" = "0" ] && [ "$nc" = "0" ]; then
	ok "T7 (a=$na b=$nb c=$nc)"
else
	fail "T7 echo: announce counts a=$na b=$nb c=$nc"
fi

# --------------------------------------------- ctl socket smoke (Phase 2)
note "ctl socket: brfsctl status/peers/backlog/journal/resync/conflicts"
ctl_ok=1
R $A "doas /tmp/brfsctl status" | grep -q "node_id: a" || { ctl_ok=0; fail "ctl status"; }
ready_n=$(R $A "doas /tmp/brfsctl peers" | grep -c "	ready	")
[ "$ready_n" = "2" ] || { ctl_ok=0; fail "ctl peers ready=$ready_n"; }
R $A "doas /tmp/brfsctl backlog" | grep -q "journal pending:" || { ctl_ok=0; fail "ctl backlog"; }
R $A "doas /tmp/brfsctl journal" | grep -q "high_seq:" || { ctl_ok=0; fail "ctl journal"; }
R $A "doas /tmp/brfsctl conflicts list" >/dev/null || { ctl_ok=0; fail "ctl conflicts list"; }
R $A "doas /tmp/brfsctl resync" | grep -q "resync requested: 2 peers" || { ctl_ok=0; fail "ctl resync"; }
[ $ctl_ok -eq 1 ] && ok "ctl socket smoke"
sleep 3   # let the requested resync settle before T8

# ------------------------------------------------------------------ T8
note "T8 kill -9 mid-FETCH"
R $A "dd if=/dev/urandom of=$TREE/big.bin bs=1m count=200 2>/dev/null"
want=$(sha_on $A $TREE/big.bin)
sleep 1   # announce out, fetch in flight
CTL $B kill9
sleep 1
CTL $B start
# 300s: on a loaded host (nightly zfs-send|xz backup hogs freebsd-dev1)
# the 1MiB-chunk pull degrades to ~1MB/s — progress, not a stall, so the
# daemon correctly never aborts; the budget must outlast a slow rig.
wait_file $B big.bin "$want" 300 && wait_file $C big.bin "$want" 300 \
	&& ok "T8" || fail "T8 kill -9"

# ----------------------------------------------------------------- T10
note "T10 rename pairs converge (no delete+create artifacts)"
R $A "echo t10 > $TREE/t10.txt"
want=$(sha_on $A $TREE/t10.txt)
# 60s: right after T8's 200MB install, receivers may still be fsyncing.
wait_file $B t10.txt "$want" 60 || fail "T10 setup b"
wait_file $C t10.txt "$want" 60 || fail "T10 setup c"
R $A "mv $TREE/t10.txt $TREE/t10-renamed.txt"
r10=0
wait_file $B t10-renamed.txt "$want" 30 || r10=1
wait_file $C t10-renamed.txt "$want" 30 || r10=1
wait_absent $B t10.txt 30 || r10=1
wait_absent $C t10.txt 30 || r10=1
for ip in $A $B $C; do
	[ "$(CTL $ip "conflicts t10")" = "0" ] || { r10=1; fail "T10 quarantine artifact on $ip"; }
done
[ $r10 -eq 0 ] && ok "T10" || fail "T10 rename"

# ---------------------------------------------------------------- done
echo
if [ "$fails" -eq 0 ]; then
	echo "REPL-TESTS PASS"
else
	echo "REPL-TESTS FAIL ($fails failures)"
	exit 1
fi
