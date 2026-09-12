#!/bin/sh
# t-ackhorizon.sh — D35 watermark ack-horizon rig proof (tombstone GC
# early collection), run on the HOST driving brfs-a/b/c over ssh.
#
# Verifies:
#   A) claims form: after initial convergence every node has BOTH peers'
#      claims recorded (RESYNC_REQ claim + WM_ECHO stream follows).
#   B) early collection: a fresh delete on A is GC-collected on A by an
#      on-demand `brfsctl gc` once BOTH peers' claims pass the tombstone's
#      journal seq — long before the 7-day TTL.
#   C) a down peer holds the horizon: with C down the same scenario on A
#      is NOT collected (C's stale claim blocks); when C returns, its
#      stream settles, the echo lands, and the next gc pass collects.
#
# Determinism notes: ControlMaster sockets live in $HOME (the /tmp
# cleaner reaps them); daemons restart with appended logs with === PHASE
# markers.  claims_ge parses brfs_member_ack_wm metrics (hex member keys
# aren't shell-computable, values are what matters).
#
# usage: sh tests/vm/t-ackhorizon.sh
set -u

A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
LOG=/tmp/brfsd.log
CTLM=$HOME/.brfs-ssh-tah
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60"
fails=0

for ip in $A $B $C; do
	ssh -MNf -o BatchMode=yes -o ConnectTimeout=60 \
		-o ControlPath=$CTLM-$ip -o ControlPersist=30m admin@$ip
done
trap 'for ip in $A $B $C; do ssh -O exit -o ControlPath=$CTLM-$ip admin@$ip 2>/dev/null; done' EXIT

note() { echo "== $*"; }
ok()   { echo "ok: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }

R() { # R <ip> <cmd>
	$SSH -o ControlPath=$CTLM-$1 admin@$1 "$2"
}

mark() { # mark <ip> <text>
	R "$1" "doas sh -c 'echo \"=== $2\" >> $LOG'"
}

dstop() {
	R "$1" 'doas pkill -x brfsd 2>/dev/null; sleep 1'
	i=0
	while R "$1" 'pgrep -x brfsd >/dev/null' && [ $i -lt 20 ]; do
		sleep 1; i=$((i + 1))
	done
	R "$1" 'pgrep -x brfsd >/dev/null' && { fail "daemon on $1 refuses to stop"; return 1; }
	return 0
}
dstart() {
	R "$1" 'doas sh -c "nohup /tmp/brfsd --config=/tmp/brfs.conf >> '$LOG' 2>&1 &"'
	i=0
	while ! R "$1" 'pgrep -x brfsd >/dev/null' && [ $i -lt 20 ]; do
		sleep 1; i=$((i + 1))
	done
	i=0
	while ! R "$1" 'doas /tmp/brfsctl status >/dev/null 2>&1' && [ $i -lt 30 ]; do
		sleep 1; i=$((i + 1))
	done
	R "$1" 'doas /tmp/brfsctl status >/dev/null 2>&1' || { fail "daemon start on $1"; R $1 "doas tail -8 $LOG"; return 1; }
	return 0
}

reset_all() {
	note "reset: stop daemons, wipe trees + state, restart"
	for ip in $A $B $C; do R $ip 'doas pkill -x brfsd 2>/dev/null; sleep 1; doas rm -rf /var/db/brfs /data/replicated; doas mkdir -p /var/db/brfs /data/replicated; doas chown admin /data/replicated; doas rm -f /tmp/brfsd.log'; done
	for ip in $A $B $C; do R $ip 'doas sh -c "nohup /tmp/brfsd --config=/tmp/brfs.conf > '"$LOG"' 2>&1 &"'; done
	sleep 8
	for ip in $A $B $C; do
		R $ip "doas grep -q 'watch root registered' $LOG" || { fail "brfsd start on $ip"; R $ip "doas tail -8 $LOG"; }
	done
}

treehash() {
	R "$1" "cd $TREE && find . -type f -exec sha256 -rq {} + | sort | sha256 -q" | tr -d ' \r\n'
}

wait_converged() { # wait_converged <timeout-s>
	tmo=$1; i=0
	while [ $i -lt "$tmo" ]; do
		ha=$(treehash $A); hb=$(treehash $B); hc=$(treehash $C)
		[ -n "$ha" ] && [ "$ha" = "$hb" ] && [ "$ha" = "$hc" ] && return 0
		sleep 2; i=$((i + 2))
	done
	echo "  (trees: a=$ha b=$hb c=$hc)"
	return 1
}

jhead() { # jhead <ip> <node-id>
	R "$1" 'doas /tmp/brfsctl metrics' 2>/dev/null | sed -n 's/^brfs_journal_seq{node="'"$2"'"} \([0-9][0-9]*\)/\1/p'
}

ntombs() { # ntombs <ip>: tombstone record count on the node
	R "$1" 'doas /tmp/brfsctl status' 2>/dev/null | sed -n 's/^records: [0-9][0-9]* live, \([0-9][0-9]*\) tombstones/\1/p'
}

claims_ge() { # claims_ge <ip> <seq>: all reported ack claims >= seq, >= 2 of them
	R "$1" 'doas /tmp/brfsctl metrics' 2>/dev/null | \
		grep '^brfs_member_ack_wm{' | sed 's/^brfs_member_ack_wm{.*} //' | \
		awk -v s="$2" '{c++; if ($1+0 < s) bad=1} END{exit (c >= 2 && !bad) ? 0 : 1}'
}

wait_claims() { # wait_claims <ip> <seq> <timeout-s>
	seq=$2; tmo=$3; i=0
	while [ $i -lt "$tmo" ]; do
		claims_ge "$1" "$seq" && return 0
		sleep 2; i=$((i + 2))
	done
	return 1
}

# ---------------------------------------------------------------- setup
reset_all

# ============================================ A: claims exist post-join
note "Phase A: seed 20 files on A; claims form on every node"
R $A 'i=0; while [ $i -lt 20 ]; do echo "seed $i" > '"$TREE"'/seed$i.txt; i=$((i + 1)); done'
wait_converged 60 || fail "phase A seed convergence"
ha=$(jhead $A a)
[ -n "$ha" ] && [ "$ha" -gt 0 ] || fail "phase A: no journal head on a (got '$ha')"
# Claims about each node's journal must exist and cover the head that
# carried the seed (allow 10 entries of raggedness past it).
for pair in "$A $ha a" "$B 0 b" "$C 0 c"; do
	set -- $pair
	tgt=$(($2 > 10 ? $2 - 10 : 0))
	wait_claims $1 $tgt 60 || fail "phase A: $3's members claims missing/low (wanted >= $tgt)"
done
ok "phase A: every node carries >= 2 member claims covering the seed"

# ============================================ B: early collection on A
note "Phase B: delete a file on A; gc collects once claims pass"
mark $A "PHASE B"; mark $B "PHASE B"; mark $C "PHASE B"
h0=$(jhead $A a)
R $A "rm $TREE/seed5.txt"
# The delete is exactly one upsert on A: the tombstone's journal seq.
i=0
while [ $i -lt 30 ]; do
	h1=$(jhead $A a)
	[ "$h1" = "$((h0 + 1))" ] && break
	sleep 1; i=$((i + 1))
done
[ "$h1" = "$((h0 + 1))" ] || fail "phase B: delete not journaled as ONE upsert (h $h0 -> $h1)"
tseq=$h1
echo "  tombstone journal seq on A: $tseq"
nt0=$(ntombs $A)
echo "  tombstones on A before gc: $nt0"
# Far inside the TTL: only the horizon may collect this.
wait_claims $A "$tseq" 90 || fail "phase B: A's members never claimed past $tseq"
res=$(R $A 'doas /tmp/brfsctl gc')
echo "  $res"
nt1=$(ntombs $A)
[ -n "$nt1" ] && [ -n "$nt0" ] && [ "$nt1" = "$((nt0 - 1))" ] \
	&& ok "phase B: tombstone early-collected long before TTL ($nt0 -> $nt1)" \
	|| fail "phase B: early collection did not fire ($nt0 -> $nt1)"
wait_converged 60 && ok "phase B: trees converged w/o the collected tombstone" || fail "phase B convergence"

# ============================================ C: a down peer holds the horizon
note "Phase C: C down; delete on A must NOT early-collect; C returns; collects"
mark $A "PHASE C"
dstop $C || fail "phase C stop"
hc0=$(jhead $C c)
h2=$(jhead $A a)
R $A "rm $TREE/seed6.txt"
i=0
while [ $i -lt 30 ]; do
	h3=$(jhead $A a)
	[ "$h3" = "$((h2 + 1))" ] && break
	sleep 1; i=$((i + 1))
done
[ "$h3" = "$((h2 + 1))" ] || fail "phase C: delete not journaled as ONE upsert (h $h2 -> $h3)"
tseq2=$h3
echo "  tombstone journal seq on A: $tseq2 (C's claim frozen at <= $hc0)"
# Let the announce + tail-push land on B; A's horizon stays BLOCKED by
# C's stale claim.  Give the follow passes their full cadence, then gc.
sleep 12
res=$(R $A 'doas /tmp/brfsctl gc')
echo "  $res"
nt2=$(ntombs $A)
[ -n "$nt2" ] && [ "$nt2" -ge 1 ] \
	&& ok "phase C: horizon held the tombstone while C was down" \
	|| fail "phase C: tombstone collected with C's claim below it ($nt2)"
wait_claims $A "$tseq2" 10 \
	&& fail "phase C: claims somehow passed the tombstone with C down" \
	|| ok "phase C: A's claims confirmed below $tseq2"

dstart $C || fail "phase C start"
wait_claims $C "$hc0" 20 >/dev/null 2>&1 || true # C resumes its own claims
wait_claims $A "$tseq2" 90 || fail "phase C: claims never passed $tseq2 after C returned"
res=$(R $A 'doas /tmp/brfsctl gc')
echo "  $res"
nt3=$(ntombs $A)
[ -n "$nt3" ] && [ "$nt3" = "$((nt2 - 1))" ] \
	&& ok "phase C: tombstone collected once C settled ($nt2 -> $nt3)" \
	|| fail "phase C: collection after C's return failed ($nt2 -> $nt3)"
wait_converged 90 && ok "phase C: mesh converged end-to-end" || fail "phase C convergence"

echo
if [ $fails -eq 0 ]; then
	echo "ACK-HORIZON PASS"
else
	echo "ACK-HORIZON FAIL ($fails failures)"
	exit 1
fi
