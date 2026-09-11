#!/bin/sh
# t-journal-resync.sh — Phase 3b watermark-diff RESYNC rig proof, run on
# the HOST driving brfs-a/b/c over ssh.
#
# Verifies:
#   A) first joins are full-record pulls; a nonempty tree's RESYNC_DONE
#      journal_head seeds the requester's per-peer watermark
#   B) an offline burst is caught up by a journal DIFF stream and the
#      mesh converges; the sender's log shows the serve's from-seq
#   C) killing the SENDER mid-stream is safe: the requester persists
#      watermark progress (every 4096 applied entries, visible as
#      brfs_journal_wm{node,peer}), and the post-kill RESYNC diff resumes
#      at a LATER journal seq than the killed attempt requested — the
#      hole the per-origin-MAX vector could not express cannot exist in a
#      contiguous journal stream
#
# Determinism notes: ssh ControlMaster sockets live in $HOME (the /tmp
# cleaner reaps them); daemons restart with appended (not wiped) logs
# with === PHASE markers, because phase log claims span restarts.
#
# usage: sh tests/vm/t-journal-resync.sh
set -u

A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
LOG=/tmp/brfsd.log
CTLM=$HOME/.brfs-ssh-trjr
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

mark() { # mark <ip> <text> — phase separator in the daemon log
	R "$1" "doas sh -c 'echo \"=== $2\" >> $LOG'"
}

# Daemon stop/start WITHOUT wiping the log (brfs-node-ctl.sh wipes).
dstop() {
	R "$1" 'doas pkill -x brfsd 2>/dev/null; sleep 1'
	i=0
	while R "$1" 'pgrep -x brfsd >/dev/null' && [ $i -lt 20 ]; do
		sleep 1; i=$((i + 1))
	done
	R "$1" 'pgrep -x brfsd >/dev/null' && { fail "daemon on $1 refuses to stop"; return 1; }
	return 0
}
dstart() { # dstart <ip> — start; verify the control socket answers
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

treehash() { # treehash <ip>
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

bwm_a() { # bwm_a: b's persisted/apply watermark for peer a (metric; empty if none)
	R $B 'doas /tmp/brfsctl metrics' 2>/dev/null | sed -n 's/^brfs_journal_wm{node="b",peer="a"} \([0-9][0-9]*\)/\1/p'
}

ahead() { # ahead: A's journal head (from A's metrics)
	R $A 'doas /tmp/brfsctl metrics' 2>/dev/null | sed -n 's/^brfs_journal_seq{node="a"} \([0-9][0-9]*\)/\1/p'
}

diff_serves_a_b() { # journal seqs A served b a diff from, oldest first
	R $A "doas grep -aF 'serving RESYNC diff to b from journal seq' $LOG" | \
		sed -n 's/.*from journal seq \([0-9][0-9]*\).*/\1/p'
}

wait_wm() { # wait_wm <floor> <timeout-s>: bwm_a >= floor
	floor=$1; tmo=$2; i=0
	while [ $i -lt "$tmo" ]; do
		w=$(bwm_a); w=${w:-0}
		[ "$w" -ge "$floor" ] && { echo "$w"; return 0; }
		sleep 1; i=$((i + 1))
	done
	echo "  (b's wm for a stuck at $w, wanted >= $floor)" >&2
	return 1
}

# ---------------------------------------------------------------- setup
reset_all

# ================================================== A: first join + seed
note "Phase A: empty-tree join must be a full pull; seed then bounce b"
R $A 'i=0; while [ $i -lt 300 ]; do echo "seed $i" > '"$TREE"'/seed$i.txt; i=$((i + 1)); done'
wait_converged 90 || fail "phase A seed convergence"
mark $A "PHASE B BOUNCE"; mark $B "PHASE B BOUNCE"
dstop $B && dstart $B || fail "phase A bounce of b"
# The bounce RESYNC full-pulls the 300-record tree and seeds b's
# watermark for a from A's journal head (DONE.journal_head).
wseed=$(wait_wm 300 60) && ok "phase A: b's wm for a seeded at $wseed" || fail "watermark never seeded after bounce"
fp=$(R $A "doas grep -a 'served RESYNC to b:' $LOG" | grep -aF '(full pull)' | head -1)
echo "  $fp"
[ -n "$fp" ] && ok "A full-pulled b (join/bounce path)" || fail "no full-pull serve to b found"

# ================================================== B: offline burst diff
note "Phase B: b offline; 500 creates + 20 deletes + 1 dir rename on A"
mark $A "PHASE B"
dstop $B || fail "phase B stop"
R $A 'i=0; while [ $i -lt 500 ]; do echo "burst $i" > '"$TREE"'/b$i.txt; i=$((i + 1)); done'
R $A 'i=0; while [ $i -lt 20 ]; do rm '"$TREE"'/seed$i.txt; i=$((i + 1)); done'
R $A "mkdir $TREE/rdir && echo x > $TREE/rdir/f.txt && sleep 1 && mv $TREE/rdir $TREE/rdir2"
dstart $B || fail "phase B start"
wprev=${wseed:-0}
# The burst is 520 mutations (500 creates + 20 deletes) + the rename pair;
# ask for 500 so commit-tick raggedness at the serve boundary can't flap.
wnew=$(wait_wm $((wprev + 500)) 90) && ok "phase B: b's wm for a advanced $wprev -> $wnew" || fail "phase B watermark stall"
dline=$(R $A "doas grep -aF 'serving RESYNC diff to b' $LOG | tail -1")
echo "  $dline"
echo "$dline" | grep -q 'from journal seq' && ok "A served b a journal diff after the burst" || fail "burst catch-up was not a journal diff"
if R $A "doas grep -a 'served RESYNC to b:' $LOG" | grep -q 'full pull'; then
	: # join-time full pulls are fine
fi
wait_converged 90 && ok "phase B: trees converged" || fail "phase B convergence"

# ===================================== C: kill -9 the sender mid-stream
note "Phase C: b offline; 5000-file burst on A; kill sender mid-stream"
mark $A "PHASE C"; mark $B "PHASE C"
dstop $B || fail "phase C stop"
R $A 'i=0; while [ $i -lt 5000 ]; do echo "big $i" > '"$TREE"'/big$i.txt; i=$((i + 1)); done'
dstart $B || fail "phase C start"
# The diff-serve attempt's from-seq (b's settled wm + 1):
csleep=0
attempt_from=""
while [ $csleep -lt 60 ]; do
	attempt_from=$(diff_serves_a_b | tail -1)
	[ -n "$attempt_from" ] && break
	sleep 1; csleep=$((csleep + 1))
done
[ -n "$attempt_from" ] || fail "phase C: no diff-serve to b started"
echo "  phase C attempt from journal seq $attempt_from"
# Kill once the requester's persisted watermark crosses one 4096 lazy
# persist boundary past the attempt's from-seq.  Applies are fetch-bound
# (a few ms each on these VMs), so 5000 entries need minutes.
target=$((attempt_from + 4096))
wk=$(wait_wm $target 300) || fail "phase C: b's wm never crossed $target before kill"
R $A 'doas pkill -9 -x brfsd'
sleep 2
mark $A "PHASE C RESUME" 2>/dev/null || true
R $A 'doas sh -c "nohup /tmp/brfsd --config=/tmp/brfs.conf >> '"$LOG"' 2>&1 &"'
sleep 6
R $A 'doas /tmp/brfsctl status >/dev/null 2>&1' || { fail "A restart after kill"; R $A "doas tail -8 $LOG"; }

# Convergence is the invariant; resume position is the watermark proof.
if wait_converged 300; then
	ok "phase C: trees converged after sender kill"
else
	fail "phase C convergence"
fi
resume_from=$(diff_serves_a_b | tail -1)
echo "  phase C resume from journal seq $resume_from"
if [ -n "$resume_from" ] && [ -n "$attempt_from" ] && [ "$resume_from" -gt "$attempt_from" ]; then
	ok "resume diff started at seq $resume_from > killed attempt's $attempt_from"
else
	fail "resume-from=$resume_from vs attempt-from=$attempt_from — watermark progress lost on kill"
fi
# Cross-check: requester's settled wm equals sender head.  The DONE that
# settles it lands AFTER content convergence is observable — poll, don't
# one-shot (rig-proven race in this exact assertion).
i=0; wf=""; hd=""
while [ $i -lt 60 ]; do
	wf=$(bwm_a); hd=$(ahead)
	[ -n "$wf" ] && [ -n "$hd" ] && [ "$wf" -ge "$((hd - 10))" ] && break
	sleep 2; i=$((i + 2))
done
echo "  final: b's wm for a=$wf, a's journal head=$hd"
[ -n "$wf" ] && [ -n "$hd" ] && [ "$wf" -ge "$((hd - 10))" ] \
	&& ok "watermarks trailed the sender head to convergence" \
	|| fail "final wm $wf trailed head $hd"

echo
if [ $fails -eq 0 ]; then
	echo "JOURNAL-RESYNC PASS"
else
	echo "JOURNAL-RESYNC FAIL ($fails failures)"
	exit 1
fi
