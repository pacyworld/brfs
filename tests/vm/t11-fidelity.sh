#!/bin/sh
# t11-fidelity.sh — T11 full event-fidelity vs the genuine inotify oracle
# UNDER LOAD, run on the HOST against brfs-a.
#
# A genuine inotify watcher (userland inotify_init/add_watch — the
# kernel's own event consumer) and `brfs-devtest dump` observe the same
# flat directory while parallel workers hammer it with create/write/
# chmod/rename/delete.  Every oracle event must appear in the brfs feed
# (same op, same name; rename cookies must pair identically).  The brfs
# feed may legitimately contain MORE (nameless self events, dedup
# boundaries); the oracle may legitimately contain fewer only when the
# ring dropped (checked: drops make the run invalid).
#
# usage: sh tests/vm/t11-fidelity.sh [seconds]
set -u
A=10.66.0.11
CTLM=/tmp/brfs-ssh-ctl
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60 -o ControlPath=$CTLM-$A"
SCP="scp -o BatchMode=yes -o ControlPath=$CTLM-$A"
SECS=${1:-20}
DIR=/data/t11-flat
fails=0

ssh -MNf -o BatchMode=yes -o ConnectTimeout=60 \
	-o ControlPath=$CTLM-$A -o ControlPersist=30m admin@$A 2>/dev/null || true
trap 'ssh -O exit -o ControlPath=$CTLM-$A admin@$A 2>/dev/null' EXIT

note() { echo "== $*"; }
ok()   { echo "ok: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }

R() { $SSH admin@$A "$1"; }

note "setup: build tools in-guest, scratch dir, kmod fresh, brfsd stopped"
$SCP /home/admin/Documents/Projects/brfs/tests/kmod/brfs-devtest.c admin@$A:/tmp/kmod-build/tests/kmod/brfs-devtest.c
$SCP /home/admin/Documents/Projects/brfs/tests/kmod/inotify-watch.c admin@$A:/tmp/kmod-build/tests/kmod/
R "cd /tmp/kmod-build && cc -O2 -o /tmp/brfs-devtest tests/kmod/brfs-devtest.c && cc -O2 -o /tmp/inotify-watch tests/kmod/inotify-watch.c" \
	|| { echo "FAIL: tool build"; exit 1; }
R "doas sh -c 'pkill -x brfsd 2>/dev/null; pkill -x brfs-devtest 2>/dev/null; pkill -x inotify-watch 2>/dev/null; sleep 1; kldunload brfs 2>/dev/null; rm -rf $DIR; mkdir -p $DIR; chown admin $DIR; kldload /tmp/kmod/brfs.ko'"

note "start brfs dump + inotify oracle"
R "doas sh -c 'nohup /tmp/brfs-devtest dump $DIR > /tmp/t11-brfs.log 2>/tmp/t11-brfs.err &'"
R "doas sh -c 'nohup /tmp/inotify-watch $DIR > /tmp/t11-ino.log 2>/tmp/t11-ino.err &'"
sleep 2
R "pgrep -x brfs-devtest >/dev/null" || { fail "dump not running"; exit 1; }
R "pgrep -x inotify-watch >/dev/null" || { fail "oracle not running"; exit 1; }

note "load: 4 parallel workers x ${SECS}s of create/write/chmod/rename/delete"
R "for w in 0 1 2 3; do ( i=0; end=\$((\$(date +%s) + $SECS)); while [ \$(date +%s) -lt \$end ]; do f=w\$w-f\$i; echo data-\$w-\$i > $DIR/\$f; chmod 600 $DIR/\$f; mv $DIR/\$f $DIR/\$f.r; rm -f $DIR/\$f.r; i=\$((i+1)); done ) & done; wait"
sleep 2
R "doas sh -c 'pkill -x brfs-devtest; pkill -x inotify-watch; sleep 1'"

drops=$(R "sysctl -n security.brfs.ring_drops" | tr -d ' \r\n')
echo "  ring drops during load: $drops"
[ "$drops" = "0" ] || fail "ring dropped during load — fidelity comparison invalid"

$SCP admin@$A:/tmp/t11-brfs.log admin@$A:/tmp/t11-ino.log /home/admin/tmp/ \
	|| { fail "log fetch"; exit 1; }
B=/home/admin/tmp/t11-brfs.log
I=/home/admin/tmp/t11-ino.log
echo "  feed lines: brfs=$(wc -l < $B | tr -d ' ') inotify=$(wc -l < $I | tr -d ' ')"

note "compare: every oracle event must appear in the brfs feed"
awk -F'\t' '
	NR == FNR {
		# brfs feed: index op+name and rename cookie pairs
		feed[$1 SUBSEP $3] = 1
		if ($1 == "MOVE_FROM") from[$2] = $3
		if ($1 == "MOVE_TO")   to[$2]   = $3
		next
	}
	{
		total++
		if (($1 SUBSEP $3) in feed) { hit++; next }
		# brfs self events (MODIFY/ATTRIB) are NAMELESS: presence check
		if (($1 == "MODIFY" || $1 == "ATTRIB") && ($1 SUBSEP "") in feed) {
			hit++
			next
		}
		missing++
		if (missing <= 10)
			printf "  MISSING in brfs feed: %s cookie=%u name=%s\n", \
			    $1, $2, $3 > "/dev/stderr"
	}
	END {
		printf "  oracle events: %d, matched: %d, missing: %d\n", \
		    total, hit, missing > "/dev/stderr"
		exit(missing > 0)
	}' "$B" "$I" 2>&1 || fail "oracle events missing from brfs feed"
[ $fails -eq 0 ] && ok "all oracle events present in brfs feed"

note "compare: rename cookie pairing"
awk -F'\t' '
	NR == FNR {
		if ($1 == "MOVE_FROM" && $2 != 0) ifrom[$2] = $3
		if ($1 == "MOVE_TO"   && $2 != 0) ito[$2]   = $3
		next
	}
	$1 == "MOVE_FROM" && $2 != 0 { bfrom[$2] = $3 }
	$1 == "MOVE_TO"   && $2 != 0 { bto[$2]   = $3 }
	END {
		bad = 0; checked = 0
		for (c in ifrom) {
			checked++
			if (!(c in bfrom) || !(c in bto) || \
			    bfrom[c] != ifrom[c] || bto[c] != ito[c]) {
				bad++
				if (bad <= 10)
					printf "  cookie %u: oracle %s->%s brfs %s->%s\n", \
					    c, ifrom[c], ito[c], bfrom[c], bto[c] > "/dev/stderr"
			}
		}
		printf "  rename cookies checked: %d, mismatched: %d\n", \
		    checked, bad > "/dev/stderr"
		exit(bad > 0)
	}' "$I" "$B" 2>&1 || fail "rename cookie pairing mismatch"
[ $fails -eq 0 ] && ok "rename cookies pair identically"

note "teardown: restore daemon"
R "doas sh -c 'kldunload brfs; kldload /tmp/kmod/brfs.ko; rm -rf $DIR'"
R "sh /tmp/brfs-node-ctl.sh start" || true

if [ "$fails" -eq 0 ]; then
	echo "T11 PASS"
else
	echo "T11 FAIL ($fails failures)"
	exit 1
fi
