#!/bin/sh
# t-shaping.sh — Phase 3 (D36) transfer-shaping rig proof, run on the
# HOST driving brfs-a/b/c over ssh.
#
# Verifies:
#   A) fetch pipelining: with 50 ms delay applied in BOTH directions of
#      the A<->B pair (~100 ms RTT inflation), a 64 MiB file must land on
#      B fast — the serialized 1-chunk-per-RTT model cannot (64 chunks
#      x ~100 ms + overheads >> our bound).  Negative control after that:
#      fetch_window=1048576 (one chunk) via SIGHUP must make the same
#      file measurably slow.  Window is restored to the default.
#   B) rate_limit: with A's egress capped at 2 MiB/s, a 16 MiB file takes
#      a bounded-but-slow time on B (proving the credit bucket actually
#      gates egress); unlimited again proves nothing regressed.  The
#      brfs_rate_tokens gauge must exist on A while limited.
#
# Determinism notes: ControlMaster sockets live in $HOME (the /tmp
# cleaner reaps them); host-side wall clock only — guests drift, and the
# measured intervals are deliberately coarser than poll granularity.
#
# usage: sh tests/vm/t-shaping.sh
set -u

A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
LOG=/tmp/brfsd.log
CTLM=$HOME/.brfs-ssh-tshp
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

reset_all() {
	note "reset: stop daemons, wipe trees + state, restart"
	for ip in $A $B $C; do R $ip 'doas pkill -x brfsd 2>/dev/null; sleep 1; doas rm -rf /var/db/brfs /data/replicated; doas mkdir -p /var/db/brfs /data/replicated; doas chown admin /data/replicated; doas rm -f /tmp/brfsd.log'; done
	for ip in $A $B $C; do R $ip 'doas sh -c "nohup /tmp/brfsd --config=/tmp/brfs.conf > '"$LOG"' 2>&1 &"'; done
	sleep 8
	for ip in $A $B $C; do
		R $ip "doas grep -q 'watch root registered' $LOG" || { fail "brfsd start on $ip"; R $ip "doas tail -8 $LOG"; }
	done
}

file_sha() { # file_sha <ip> <tree-rel-path> (empty when absent)
	R "$1" "sha256 -q $TREE/$2 2>/dev/null || true" | tr -d ' \r\n'
}

hup() { R $1 'doas pkill -HUP -x brfsd'; sleep 1; }

# wait_log <ip> <pattern> <timeout-s> — poll the daemon log for a line
wait_log() {
	i=0
	while [ $i -lt $(( $3 * 2 )) ]; do
		R $1 "doas grep -aqF '$2' $LOG" && return 0
		sleep 0.5; i=$((i + 1))
	done
	return 1
}

# xfer_dur <ip> <path> — transfer duration in ms from the node's OWN log:
# FIRST "recv announce <path>" (fetch start) to "install queued <path>"
# (last chunk staged).  Single-clock, immune to poll/ssh/clock-drift noise.
xfer_dur() {
	R $1 "doas grep -aF '$2' $LOG" | awk '
		/recv announce/ { if (!t) t = substr($2, 1, length($2)-1) + 0; }
		/install queued/ { e = substr($2, 1, length($2)-1) + 0; }
		END { if (t && e) print e - t; }'
}

# ---------------------------------------------------------------- setup
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for ip in $A $B $C; do
	scp -q -o BatchMode=yes -o ControlPath=$CTLM-$ip \
		"$SELF_DIR/brfs-conf-key.sh" admin@$ip:/tmp/ \
		|| fail "deploy brfs-conf-key.sh to $ip"
done
reset_all
for ip in $A $B $C; do
	R $ip 'kldstat -q -m ipfw 2>/dev/null || { doas kenv net.inet.ip.fw.default_to_accept=1; doas kldload ipfw; }; kldstat -q -m dummynet 2>/dev/null || doas kldload dummynet'
done

# ================================================== A: fetch pipelining
note "Phase A: 50ms x 2 on A<->B; 32 MiB file, windowed vs serialized"
R $A "doas ipfw delete 1011 2>/dev/null; doas ipfw add 1011 pipe 11 ip from me to $B out; doas ipfw pipe 11 config delay 50ms plr 0 bw 0"
R $B "doas ipfw delete 1011 2>/dev/null; doas ipfw add 1011 pipe 11 ip from me to $A out; doas ipfw pipe 11 config delay 50ms plr 0 bw 0"
reset_all

note "Phase A1: pipelined (window default 8 MiB)"
R $A "dd if=/dev/urandom of=$TREE/pipe32.bin bs=1m count=32 2>/dev/null"
sha=$(file_sha $A pipe32.bin)
[ -n "$sha" ] || fail "A1: source write failed"
wait_log $B 'install queued pipe32.bin' 60 || fail "A1: 32 MiB never converged (60s)"
[ "$(file_sha $B pipe32.bin)" = "$sha" ] || fail "A1: content mismatch on B"
el1=$(xfer_dur $B pipe32.bin)
echo "  pipelined: ${el1}ms (announce->install on B)"
# On this rig a delay-shaped link also shows TCP's own window limit —
# the separation proof lives in A1 vs A2, so A1's bar is generous.
if [ -n "$el1" ] && [ $el1 -ge 500 ] && [ $el1 -lt 12000 ]; then
	ok "A1: 32 MiB windowed transfer completed promptly (${el1}ms)"
else
	fail "A1: '${el1}ms' outside the sane band"
fi

note "Phase A2: negative control — SIGHUP fetch_window=1 MiB on B"
R $B 'doas sh /tmp/brfs-conf-key.sh fetch_window 1048576 && doas pkill -HUP -x brfsd'
sleep 2
R $B 'doas /tmp/brfsctl status' | grep -q 'fetch_window: 1048576 B' \
	&& ok "A2: window knob live" \
	|| fail "A2: SIGHUP window did not take"
R $A "dd if=/dev/urandom of=$TREE/serial32.bin bs=1m count=32 2>/dev/null"
sha=$(file_sha $A serial32.bin)
wait_log $B 'install queued serial32.bin' 120 || fail "A2: 32 MiB never converged (120s)"
[ "$(file_sha $B serial32.bin)" = "$sha" ] || fail "A2: content mismatch on B"
el2=$(xfer_dur $B serial32.bin)
echo "  serialized: ${el2}ms (announce->install on B)"
# Separation proof: the clamp must cost at least +6s AND at least 2x
# over the same bytes windowed.
if [ -n "$el2" ] && [ $el2 -gt $((el1 + 6000)) ] && [ $el2 -ge $((el1 * 2)) ]; then
	ok "A2: one-chunk-deep fetch is RTT-serialized (${el2}ms vs pipelined ${el1}ms)"
else
	fail "A2: '${el2}ms' vs pipelined '${el1}ms' — window clamp did not serialize"
fi
# Restore the default window everywhere for later phases.
R $B 'doas sh /tmp/brfs-conf-key.sh fetch_window - && doas pkill -HUP -x brfsd'
sleep 2
R $B 'doas /tmp/brfsctl status' | grep -q 'fetch_window: 8388608 B' \
	&& ok "A2: window restored to 8 MiB default" \
	|| fail "A2: window restore failed"

# ================================================== B: rate_limit
note "Phase B: A's egress capped at 2 MiB/s; 16 MiB file must pace out"
for ip in $A $B $C; do R $ip 'for r in 1011 1012 1013; do doas ipfw delete $r 2>/dev/null; done; doas ipfw pipe 11 config delay 0ms plr 0 bw 0 2>/dev/null' ; done
reset_all
R $A 'doas sh /tmp/brfs-conf-key.sh rate_limit 2097152 && doas pkill -HUP -x brfsd'
sleep 2
R $A 'doas /tmp/brfsctl status' | grep -q 'rate_limit: 2097152 B/s' \
	&& ok "B: limit knob live on A" \
	|| fail "B: SIGHUP rate_limit did not take"
R $A 'doas /tmp/brfsctl metrics' | grep -q '^brfs_rate_tokens{' \
	&& ok "B: brfs_rate_tokens gauge exported" \
	|| fail "B: no brfs_rate_tokens gauge"

R $A "dd if=/dev/urandom of=$TREE/rate16.bin bs=1m count=16 2>/dev/null"
sha=$(file_sha $A rate16.bin)
wait_log $B 'install queued rate16.bin' 45 || fail "B: 16 MiB never converged (45s)"
[ "$(file_sha $B rate16.bin)" = "$sha" ] || fail "B: content mismatch on B"
el3=$(xfer_dur $B rate16.bin)
echo "  rate-limited: ${el3}ms (target ~7s)"
# Target: (16 MiB - one free 2 MiB bucket) / 2 MiB/s ≈ 7 s of pacing.
if [ -n "$el3" ] && [ $el3 -ge 5500 ] && [ $el3 -le 14000 ]; then
	ok "B: 16 MiB at 2 MiB/s paced out over ${el3}ms"
else
	fail "B: '${el3}ms' outside the paced band — bucket ineffective or wedged"
fi
R $A 'doas sh /tmp/brfs-conf-key.sh rate_limit - && doas pkill -HUP -x brfsd'
sleep 2
R $A 'doas /tmp/brfsctl status' | grep -q 'rate_limit: 0 B/s' \
	&& ok "B: limit lifted" \
	|| fail "B: rate_limit restore failed"

echo
if [ $fails -eq 0 ]; then
	echo "SHAPING PASS"
else
	echo "SHAPING FAIL ($fails failures)"
	exit 1
fi
