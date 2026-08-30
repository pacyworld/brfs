#!/bin/sh
# t21-t24-wan.sh — WAN/chaos track T21-T24, run on the HOST (freebsd-dev1)
# driving the brfs-a/b/c bhyve rig over ssh.
#
# Expects per node: /tmp/brfsd, /tmp/brfsctl, /tmp/brfs.conf,
# /tmp/brfs.psk, /tmp/brfs-node-ctl.sh (guest-side helper), brfs.ko
# loaded, admin ssh + doas nopass, TLS certs deployed.  This script
# deploys /tmp/brfs-wan-ctl.sh itself.
#
# Impairment mechanism: dummynet pipes scoped to peer-pair traffic — one
# OUTBOUND rule per peer per node matching all IP between the pair; ssh
# from the host (10.66.0.1) never matches, so impairment cannot lock out
# the control channel.  (PLAN.md's sanctioned fallback: ng_netem is GONE
# from FreeBSD 15.1.  dummynet delay/plr/bw are all TLS+KTLS-clean once
# brfsd's nonblocking SSL_write handling was fixed — before that fix,
# delayed links killed TLS bulk transfers.  ng_pipe was validated as an
# L2 alternative and abandoned: it impairs ssh and its 100Hz tick
# inflates configured delays.)
#
# Delay accounting: with delay D ms configured outbound on both ends of a
# link the added link RTT is ~2*D (kern.hz=100 quantizes to 10ms ticks);
# T21 reports the MEASURED ping RTT per tier.
#
#   T21 latency ~25/50/100ms-class link RTT — convergence holds,
#       stall detector must not false-fire (it's a progress detector,
#       not a deadline), no wbuf saturation.
#   T22 loss 0.5%/2% plr — TCP hides it; hash-mismatch requeue stays
#       bounded (zero expected over TLS+TCP), no re-fetch loop (served-
#       chunk count bounded vs. expected), no stalls.
#   T23 bandwidth cap 10/1 Mbps — 10Mbps: sub-cap burst converges clean
#       (no saturation, no stalls).  1Mbps: burst over the 64MiB wbuf
#       cap drops the conn ("send queue saturated"), backoff+dial
#       suppression retry without livelock, RESYNC heals to full
#       convergence after the cap lifts.
#   T24 partition — node C fully cut (plr 1 both directions on both of
#       its links) for ~3 minutes of writes at WAN RTT, then heal and
#       full convergence via RESYNC.
#
# usage: sh tests/vm/t21-t24-wan.sh [TEST]
#   Run all tests, or a single named test (t21, t22, t23, t24).
set -u

A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
# Control sockets + poll tempfiles live under $HOME: a host /tmp cleaner
# reaped /tmp/brfs-ssh-ctl-* mid-session (2026-08-29), silently dropping
# every call back to a slow direct handshake.
CTLM=$HOME/.brfs-ssh/ctl
TMPD=$HOME/.brfs-ssh
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60 -o ControlPath=$CTLM-%h"
fails=0
ONLY="${1:-}"

# Connection reuse
mkdir -p "$TMPD"
for ip in $A $B $C; do
	ssh -MNf -o BatchMode=yes -o ConnectTimeout=60 \
		-o ControlPath=$CTLM-$ip -o ControlPersist=4h admin@$ip 2>/dev/null || true
done

note() { echo "== $*"; }
ok()   { echo "ok: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }

R() { $SSH admin@"$1" "$2"; }

CTL() { $SSH admin@"$1" "sh /tmp/brfs-node-ctl.sh $2"; }

WAN() { ip=$1; shift; $SSH admin@"$ip" "sh /tmp/brfs-wan-ctl.sh $*"; }

peers_of() {
	case "$1" in
	$A) echo "$B $C" ;;
	$B) echo "$A $C" ;;
	*)  echo "$A $B" ;;
	esac
}

name_of() {
	case "$1" in
	$A) echo a ;;
	$B) echo b ;;
	*)  echo c ;;
	esac
}

# wan_set_all <delay-ms|-> <plr|-> <bw|-> — uniform impairment: every
# node's outbound pipe to each peer gets the same config.
wan_set_all() {
	for ip in $A $B $C; do
		for peer in $(peers_of $ip); do
			WAN $ip set "${peer##*.}" "$peer" "$1" "$2" "$3"
		done
	done
}

# wan_unset_link <ip> <peer> — remove one direction's impairment.
wan_unset_link() { WAN "$1" set "${2##*.}" "$2" - - -; }

wan_clear_all() { for ip in $A $B $C; do WAN $ip clear; done; }

# measured RTT A->B (avg ms, decimal) — dummynet at kern.hz=100 quantizes
# configured delays to 10ms ticks, so tiers report the measured value.
measure_rtt() {
	R $A "ping -c 5 -q $B 2>/dev/null | tail -1" | awk -F/ '{print $5}'
}

trap 'wan_clear_all >/dev/null 2>&1; for ip in $A $B $C; do ssh -O exit -o ControlPath=$CTLM-$ip admin@$ip 2>/dev/null; done' EXIT

sha_on() { R "$1" "sha256 -q $2 2>/dev/null" | tr -d ' \r\n'; }

count_on() { CTL "$1" "logcount $2" | tr -d ' \r\n'; }
# NOTE: the stall pattern avoids parens — CTL interpolates the pattern
# unquoted into a remote sh command line, and "(...) " is a syntax error.
stalls_on()  { count_on "$1" "no progress"; }
sat_on()     { count_on "$1" "send queue saturated"; }
mism_on()    { count_on "$1" "hash mismatch"; }
serving_on() { count_on "$1" ": serving"; }

# write_files <ip> <prefix> <n> <size-kb> — n files named <prefix>-<i>.bin
write_files() {
	R "$1" "i=0; while [ \$i -lt $3 ]; do dd if=/dev/urandom of=$TREE/$2-\$i.bin bs=1k count=$4 2>/dev/null; i=\$((i+1)); done"
}

# wait_batch <prefix> <n> <src-ip> <dst-ip> <timeout-s> — all n files'
# sha256 on dst must equal src's.  Two ssh calls per poll round.
wait_batch() {
	prefix=$1; n=$2; src=$3; dst=$4; tmo=$5; i=0
	R $src "i=0; while [ \$i -lt $n ]; do sha256 -q $TREE/$prefix-\$i.bin 2>/dev/null || echo NONE; i=\$((i+1)); done" > $TMPD/wan-want.$$
	while [ $i -lt $((tmo * 2)) ]; do
		R $dst "i=0; while [ \$i -lt $n ]; do sha256 -q $TREE/$prefix-\$i.bin 2>/dev/null || echo NONE; i=\$((i+1)); done" > $TMPD/wan-got.$$
		if cmp -s $TMPD/wan-want.$$ $TMPD/wan-got.$$; then
			rm -f $TMPD/wan-want.$$ $TMPD/wan-got.$$
			return 0
		fi
		sleep 0.5; i=$((i + 1))
	done
	echo "  (wait_batch timeout: $prefix x$n on $dst)"
	rm -f $TMPD/wan-want.$$ $TMPD/wan-got.$$
	return 1
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

reset_all() {
	note "reset: stop daemons, wipe trees + state, restart"
	for ip in $A $B $C; do CTL "$ip" reset; done
	for ip in $A $B $C; do CTL "$ip" start; done
	sleep 8
	for ip in $A $B $C; do
		CTL "$ip" started || { fail "brfsd start on $ip"; CTL "$ip" log 8; }
	done
}

should_run() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

# ------------------------------------------------------------- setup
note "setup: deploy wan helper, safe ipfw/dummynet init on all nodes"
for ip in $A $B $C; do
	scp -o BatchMode=yes -o ControlPath=$CTLM-$ip \
		tests/vm/brfs-wan-ctl.sh admin@$ip:/tmp/brfs-wan-ctl.sh || {
		echo "FATAL: deploy wan helper to $ip"; exit 1; }
	WAN $ip init || { echo "FATAL: wan init on $ip"; exit 1; }
	WAN $ip clear
done

# ----------------------------------------------------------------- T21
if should_run t21; then
note "T21 latency: convergence holds, no stall false-fire (dummynet delay)"
t21_ok=1
# Per-direction outbound delay (ms) on both ends of every link; measured
# link RTT is reported per tier (dummynet quantizes to 10ms ticks).
for D in 12 25 50; do
	wan_set_all $D - -
	rtt=$(measure_rtt)
	note "  T21 tier ${D}ms/dir (measured A-B RTT ${rtt}ms)"
	reset_all
	t0=$(date +%s)
	for ip in $A $B $C; do write_files $ip t21-$(name_of $ip) 4 1024; done
	for ip in $A $B $C; do
		p=t21-$(name_of $ip)
		for dst in $(peers_of $ip); do
			wait_batch $p 4 $ip $dst 300 || t21_ok=0
		done
	done
	el=$(( $(date +%s) - t0 ))
	for ip in $A $B $C; do
		st=$(stalls_on $ip)
		[ "$st" = "0" ] || { t21_ok=0; fail "T21 ${D}ms: stall false-fire on $ip ($st)"; }
		sq=$(sat_on $ip)
		[ "$sq" = "0" ] || { t21_ok=0; fail "T21 ${D}ms: wbuf saturation on $ip ($sq)"; }
	done
	note "  T21 ${D}ms/dir tier converged in ${el}s, stalls=0"
done
wan_clear_all
[ $t21_ok -eq 1 ] && ok "T21"
fi

# ----------------------------------------------------------------- T22
if should_run t22; then
note "T22 loss: 0.5%/2% plr — convergence holds, hash-mismatch requeue bounded"
t22_ok=1
for P in 0.005 0.02; do
	note "  T22 tier plr=$P per direction"
	wan_set_all - $P -
	reset_all
	write_files $A t22-a 8 1024
	R $A "dd if=/dev/urandom of=$TREE/t22-big.bin bs=1m count=16 2>/dev/null"
	big=$(sha_on $A $TREE/t22-big.bin)
	for dst in $B $C; do
		wait_batch t22-a 8 $A $dst 300 || t22_ok=0
		wait_file $dst t22-big.bin "$big" 300 || t22_ok=0
	done
	for ip in $A $B $C; do
		hm=$(mism_on $ip)
		[ "$hm" = "0" ] || { t22_ok=0; fail "T22 plr=$P: hash mismatch on $ip ($hm)"; }
		st=$(stalls_on $ip)
		[ "$st" = "0" ] || { t22_ok=0; fail "T22 plr=$P: stall on $ip ($st)"; }
	done
	# Bounded re-fetch: 8x1-chunk + 1x16-chunk files, 2 requesters each =
	# exactly 48 chunk services expected; fail past 3x (re-fetch loop).
	sv=$(serving_on $A)
	note "  T22 plr=$P: A served $sv chunks (expected 48, bound 144)"
	[ "$sv" -le 144 ] || { t22_ok=0; fail "T22 plr=$P: re-fetch loop on A (served $sv)"; }
done
wan_clear_all
[ $t22_ok -eq 1 ] && ok "T22"
fi

# ----------------------------------------------------------------- T23
if should_run t23; then
note "T23 bandwidth cap: 10Mbps clean-slow, 1Mbps wbuf saturation + resync heal"
t23_ok=1

# Phase 1: 10 Mbps, 32MiB burst — under the 64MiB wbuf cap: no drops.
note "  T23 phase 1: 10Mbps, 32 x 1MiB burst (under 64MiB wbuf cap)"
wan_set_all - - 10Mbit/s
reset_all
t0=$(date +%s)
write_files $A t23a 32 1024
for dst in $B $C; do
	wait_batch t23a 32 $A $dst 600 || t23_ok=0
done
el=$(( $(date +%s) - t0 ))
for ip in $A $B $C; do
	sq=$(sat_on $ip)
	[ "$sq" = "0" ] || { t23_ok=0; fail "T23 10Mbps: unexpected wbuf saturation on $ip ($sq)"; }
	st=$(stalls_on $ip)
	[ "$st" = "0" ] || { t23_ok=0; fail "T23 10Mbps: stall on $ip ($st)"; }
done
note "  T23 10Mbps phase converged in ${el}s (32MiB, no saturation)"

# Phase 2: 1 Mbps, 96MiB burst — over the cap: wbuf saturation must drop
# the conn; backoff retries without livelock; full heal after cap lifts.
note "  T23 phase 2: 1Mbps, 96 x 1MiB burst (over 64MiB wbuf cap)"
wan_set_all - - 1Mbit/s
reset_all
write_files $A t23b 96 1024
sleep 150   # observation window: saturation/drop/backoff cycles
sq=$(sat_on $A)
if [ "$sq" -ge 1 ] 2>/dev/null; then
	note "  T23 1Mbps: A logged $sq send-queue saturation drops in 150s"
else
	t23_ok=0; fail "T23 1Mbps: wbuf saturation never fired on A (sq=$sq)"
fi
for ip in $A $B $C; do
	CTL $ip started || { t23_ok=0; fail "T23 1Mbps: brfsd down on $ip"; }
done
landed=$(R $B "ls $TREE 2>/dev/null | grep -c '^t23b-'" | tr -d ' \r\n')
note "  T23 1Mbps: $landed/96 files landed on B during the cap window"
if [ "$landed" -ge 1 ] 2>/dev/null; then :; else
	t23_ok=0; fail "T23 1Mbps: zero progress under cap (livelock)"
fi
note "  T23: lifting cap, awaiting full convergence"
wan_clear_all
R $A "doas /tmp/brfsctl resync" >/dev/null 2>&1 || true
for dst in $B $C; do
	wait_batch t23b 96 $A $dst 600 || t23_ok=0
done
[ $t23_ok -eq 1 ] && ok "T23"
fi

# ----------------------------------------------------------------- T24
if should_run t24; then
note "T24 partition: node C cut for ~3min of writes at 50ms RTT, heal, RESYNC convergence"
t24_ok=1
reset_all
wan_set_all 25 - -   # WAN-RTT baseline on every link
rtt=$(measure_rtt)
note "  T24 baseline RTT ${rtt}ms"
# Partition C: plr 1 outbound on both ends of both of C's links.
for peer in $(peers_of $C); do WAN $C set "${peer##*.}" "$peer" - 1 -; done
for ip in $A $B;  do WAN $ip set "${C##*.}" "$C" - 1 -; done

# ~3 minutes of writes: A heavy (3 batches), B light, C local-only.
write_files $A t24-a  10 256
sleep 60
write_files $A t24-a2 10 256
write_files $B t24-b  3 256
write_files $C t24-c  2 256
sleep 60
write_files $A t24-a3 10 256
write_files $B t24-b2 3 256
write_files $C t24-c2 2 256
sleep 60

# The partition must have held in both directions.
R $C "test -e $TREE/t24-a-0.bin" && { t24_ok=0; fail "T24 partition leaked: A's file on C"; }
R $C "test -e $TREE/t24-b-0.bin" && { t24_ok=0; fail "T24 partition leaked: B's file on C"; }
R $A "test -e $TREE/t24-c-0.bin" && { t24_ok=0; fail "T24 partition leaked: C's file on A"; }

note "  T24: healing partition (WAN-RTT baseline stays), forcing RESYNC"
for peer in $(peers_of $C); do wan_unset_link $C $peer; done
for ip in $A $B;  do wan_unset_link $ip $C; done
for ip in $A $B $C; do R $ip "doas /tmp/brfsctl resync" >/dev/null 2>&1 || true; done

# Full convergence at WAN scale: every batch on every node.
for p in "t24-a 10" "t24-a2 10" "t24-a3 10"; do
	set -- $p
	for dst in $B $C; do wait_batch $1 $2 $A $dst 600 || t24_ok=0; done
done
for p in "t24-b 3" "t24-b2 3"; do
	set -- $p
	for dst in $A $C; do wait_batch $1 $2 $B $dst 600 || t24_ok=0; done
done
for p in "t24-c 2" "t24-c2 2"; do
	set -- $p
	for dst in $A $B; do wait_batch $1 $2 $C $dst 600 || t24_ok=0; done
done

# No conflicts: all writes were to disjoint paths.
for ip in $A $B $C; do
	cq=$(CTL $ip "conflicts t24")
	[ "$cq" = "0" ] || { t24_ok=0; fail "T24 quarantine artifact on $ip ($cq)"; }
done
wan_clear_all
[ $t24_ok -eq 1 ] && ok "T24"
fi

# ---------------------------------------------------------------- done
echo
if [ "$fails" -eq 0 ]; then
	echo "WAN-TESTS PASS"
else
	echo "WAN-TESTS FAIL ($fails failures)"
	exit 1
fi
