#!/bin/sh
# t-rdc.sh — Phase 3 (D37) RDC-delta rig proof, run on the HOST driving
# brfs-a/b/c over ssh.  Requires the v4-protocol binaries deployed on all
# three nodes (HELLO refuses protocol mismatches).
#
# Verifies:
#   A) same-path delta: a 1 MiB edit inside a 16 MiB file replicates with
#      mostly LOCAL chunk copies on the receivers (copy_bytes high,
#      literal_bytes small), content identical.
#   B) cross-file seed: a NEW file that shares content with an existing
#      one transfers only its novel bytes (the "bring your own basis"
#      case DFSR needs similarity hashing for; BrFS's content-addressed
#      index gets it for free).
#   C) fallbacks: C1 sender-side rdc=false (nack_no_rdc downgrade to a
#      plain pull), C2 receiver-side rdc=false (no manifest requested),
#      C3 a stale index entry (offline byte overwrite with mtime fixed
#      back, so the record stays "unchanged") must be caught by
#      verify-on-use and fall back to literal bytes — content correct.
#
# Metrics are read from each RECEIVER's brfsctl metrics (daemon-local
# counters, reset by reset_all).
#
# usage: sh tests/vm/t-rdc.sh
set -u

A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
LOG=/tmp/brfsd.log
CTLM=$HOME/.brfs-ssh-trdc
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

R() { $SSH -o ControlPath=$CTLM-$1 admin@$1 "$2"; }

reset_all() {
	note "reset: stop daemons, wipe trees + state, restart"
	for ip in $A $B $C; do R $ip 'doas pkill -x brfsd 2>/dev/null; sleep 1; doas rm -rf /var/db/brfs /data/replicated; doas mkdir -p /var/db/brfs /data/replicated; doas chown admin /data/replicated; doas rm -f /tmp/brfsd.log'; done
	for ip in $A $B $C; do R $ip 'doas sh -c "nohup /tmp/brfsd --config=/tmp/brfs.conf > '"$LOG"' 2>&1 &"'; done
	sleep 8
	for ip in $A $B $C; do
		R $ip "doas grep -q 'watch root registered' $LOG" || { fail "brfsd start on $ip"; R $ip "doas tail -8 $LOG"; }
	done
}

file_sha() { R "$1" "sha256 -q $TREE/$2 2>/dev/null || true" | tr -d ' \r\n'; }

wait_log() { # wait_log <ip> <pattern> <timeout-s>
	i=0
	while [ $i -lt $(( $3 * 2 )) ]; do
		R $1 "doas grep -aqF '$2' $LOG" && return 0
		sleep 0.5; i=$((i + 1))
	done
	return 1
}

metric() { # metric <ip> <name> — value or empty
	R $1 "doas /tmp/brfsctl metrics 2>/dev/null | grep '^$2{'" | awk '{print $2}'
}

converge2() { # converge2 <relpath> <timeout> — B and C must match A's sha
	# NOTE: installs are atomic (rename at end), so a single equal sha
	# triplet is a valid convergence sample.  Log-line waits are racy
	# ("install queued <path>" matches STALE entries from earlier rounds).
	sha=$(file_sha $A $1)
	[ -n "$sha" ] || { fail "converge: source $1 unreadable on A"; return 1; }
	i=0
	while [ $i -lt $(( $2 * 2 )) ]; do
		sb=$(file_sha $B $1); sc=$(file_sha $C $1)
		if [ "$sb" = "$sha" ] && [ "$sc" = "$sha" ]; then return 0; fi
		sleep 0.5; i=$((i + 1))
	done
	fail "converge: $1 (A=$sha B='$sb' C='$sc')"
	return 1
}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for ip in $A $B $C; do
	scp -q -o BatchMode=yes -o ControlPath=$CTLM-$ip \
		"$SELF_DIR/brfs-conf-key.sh" admin@$ip:/tmp/ \
		|| fail "deploy brfs-conf-key.sh to $ip"
done
# Fresh indexes and knobs for the run.
for ip in $A $B $C; do
	R $ip 'doas sh /tmp/brfs-conf-key.sh rdc - >/dev/null 2>&1; doas sh /tmp/brfs-conf-key.sh rdc_min - >/dev/null 2>&1; true'
done
reset_all

# ================================================== A: same-path delta
note "Phase A: 16 MiB random, then a 1 MiB mid-file edit"
R $A "dd if=/dev/urandom of=$TREE/deltaA.bin bs=1m count=16 2>/dev/null"
converge2 deltaA.bin 90 || true
lc0=$(metric $B brfs_rdc_literal_bytes); cc0=$(metric $B brfs_rdc_copy_bytes)
echo "  B after seed: literal=${lc0:-0} copy=${cc0:-0}"
# Seed transfer is all-novel content: literals dominate.
[ -n "$lc0" ] && [ "${cc0:-0}" -lt "${lc0:-1}" ] \
	&& ok "A0: fresh content transferred as literals (lit=$lc0)" \
	|| fail "A0: unexpected lit/copy for fresh content (lit=$lc0 copy=$cc0)"

R $A "dd if=/dev/urandom of=$TREE/deltaA.bin bs=1m count=1 seek=6 conv=notrunc 2>/dev/null"
converge2 deltaA.bin 90 || true
lc1=$(metric $B brfs_rdc_literal_bytes); cc1=$(metric $B brfs_rdc_copy_bytes)
dl=$(( ${lc1:-0} - ${lc0:-0} )); dc=$(( ${cc1:-0} - ${cc0:-0} ))
echo "  B edit transfer: literal=$dl copy=$dc"
# 15/16 of the file is local; cut-boundary spill can lift literals a
# couple of chunks past 1 MiB.  Bars: copy >= 12 MiB, literal <= 4 MiB.
if [ "$dc" -ge 12582912 ] && [ "$dl" -le 4194304 ]; then
	ok "A1: 1 MiB edit replicated as delta (copy=${dc}B lit=${dl}B)"
else
	fail "A1: delta ineffective (copy=${dc}B lit=${dl}B)"
fi

# ================================================== B: cross-file seed
note "Phase B: new file = 15 MiB of seed + 1 MiB novel tail"
R $A "dd if=$TREE/deltaA.bin of=$TREE/crossB.bin bs=1m count=15 2>/dev/null && dd if=/dev/urandom of=$TREE/crossB.bin bs=1m count=1 seek=15 conv=notrunc 2>/dev/null"
converge2 crossB.bin 90 || true
lc2=$(metric $B brfs_rdc_literal_bytes); cc2=$(metric $B brfs_rdc_copy_bytes)
dl2=$(( ${lc2:-0} - ${lc1:-0} )); dc2=$(( ${cc2:-0} - ${cc1:-0} ))
echo "  B cross-file transfer: literal=$dl2 copy=$dc2"
if [ "$dc2" -ge 12582912 ] && [ "$dl2" -le 4194304 ]; then
	ok "B1: cross-file seeds dedup (copy=${dc2}B lit=${dl2}B)"
else
	fail "B1: cross-file dedup ineffective (copy=${dc2}B lit=${dl2}B)"
fi

# ================================================== C: fallbacks
note "Phase C1: sender rdc=false -> nack_no_rdc downgrade pulls whole"
R $A 'doas sh /tmp/brfs-conf-key.sh rdc false && doas pkill -HUP -x brfsd'
sleep 2
R $A 'doas /tmp/brfsctl status' | grep -q 'rdc: off' \
	|| fail "C1: rdc=off not live on A"
R $A "dd if=/dev/urandom of=$TREE/downC1.bin bs=1m count=8 2>/dev/null"
converge2 downC1.bin 60 || true
i=0; downgraded=no
while [ $i -lt 20 ]; do
	R $B "doas grep -aq 'downgrading to whole-file pull' $LOG" && { downgraded=yes; break; }
	sleep 0.5; i=$((i + 1))
done
[ "$downgraded" = yes ] \
	&& ok "C1: receiver downgraded on nack_no_rdc" \
	|| fail "C1: no nack_no_rdc downgrade logged on B"
R $A 'doas sh /tmp/brfs-conf-key.sh rdc - && doas pkill -HUP -x brfsd'
sleep 2

note "Phase C2: receiver rdc=false -> plain whole-file pull (no manifest)"
R $B 'doas sh /tmp/brfs-conf-key.sh rdc false && doas pkill -HUP -x brfsd'
sleep 2
R $A "dd if=/dev/urandom of=$TREE/downC2.bin bs=1m count=8 2>/dev/null"
converge2 downC2.bin 60 || true
if R $B "doas grep -aq 'rdc fetch downC2.bin' $LOG"; then
	fail "C2: receiver still requested a manifest despite rdc=false"
else
	ok "C2: receiver-side rdc=false = plain pull"
fi
R $B 'doas sh /tmp/brfs-conf-key.sh rdc - && doas pkill -HUP -x brfsd'
sleep 2

note "Phase C3: stale index entry caught by verify-on-use"
# Capture the content + identity of an indexed file; brfsd on B must not
# observe the tamper (daemon down, size/inode preserved, mtime fixed).
R $A "dd if=/dev/urandom of=$TREE/staleC3.bin bs=1m count=8 2>/dev/null"
converge2 staleC3.bin 60 || true
stale_mtime=$(R $B "stat -f %Sm -t %Y%m%d%H%M.%S $TREE/staleC3.bin" | tr -d ' \r\n')
stale_size=$(R $B "stat -f %z $TREE/staleC3.bin" | tr -d ' \r\n')
[ -n "$stale_mtime" ] && [ -n "$stale_size" ] || fail "C3: cannot stat staleC3.bin on B"
R $B 'doas pkill -x brfsd; sleep 1'
# Installed files are root-owned (brfsd runs as root) — the tamper MUST
# go through doas; a plain dd fails EACCES and the "stale" index isn't.
R $B "doas dd if=/dev/zero of=$TREE/staleC3.bin bs=1m count=8 conv=notrunc 2>/dev/null; doas touch -t $stale_mtime $TREE/staleC3.bin"
tampered=$(R $B "sha256 -q $TREE/staleC3.bin")
[ "$tampered" != "$(file_sha $A staleC3.bin)" ] \
	&& ok "C3: tamper on B confirmed" \
	|| fail "C3: dd tamper did not take (test invalid)"
R $B 'doas sh -c "nohup /tmp/brfsd --config=/tmp/brfs.conf > '"$LOG"' 2>&1 &"'
wait_log $B 'watch root registered' 60 || fail "C3: brfsd restart on B"
# Absorption check: B must NOT announce a local edit of staleC3.bin.
if R $B "doas grep -aq 'announce staleC3.bin' $LOG"; then
	fail "C3: B announced the offline tamper (identity absorb failed) — test invalid"
else
	ok "C3a: offline tamper absorbed (index genuinely stale now)"
fi
cop0=$(metric $B brfs_rdc_copy_bytes); lit0=$(metric $B brfs_rdc_literal_bytes)
R $A "cp $TREE/staleC3.bin $TREE/staledstC3.bin && dd if=/dev/urandom of=$TREE/staledstC3.bin bs=1m count=1 seek=4 conv=notrunc 2>/dev/null"
converge2 staledstC3.bin 60 || true
cop1=$(metric $B brfs_rdc_copy_bytes); lit1=$(metric $B brfs_rdc_literal_bytes)
dcop=$(( ${cop1:-0} - ${cop0:-0} )); dlit=$(( ${lit1:-0} - ${lit0:-0} ))
echo "  B stale-seed transfer: copy=$dcop literal=$dlit"
# No chunk may be copied from the tampered source: verify-on-use fails
# every candidate, so bytes arrive as literals.
if [ "$dcop" -eq 0 ] && [ "$dlit" -ge 7340032 ]; then
	ok "C3b: stale seeds rejected byte-for-byte (copy=$dcop lit=$dlit)"
else
	fail "C3b: stale bytes copied or literals short (copy=$dcop lit=$dlit)"
fi
[ "$(file_sha $B staledstC3.bin)" = "$(file_sha $A staledstC3.bin)" ] \
	&& ok "C3c: content correct despite stale index" \
	|| fail "C3c: content mismatch on B"

echo
if [ $fails -eq 0 ]; then
	echo "RDC PASS"
else
	echo "RDC FAIL ($fails failures)"
	exit 1
fi
