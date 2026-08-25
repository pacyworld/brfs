#!/bin/sh
# tap-smoke.sh — P0.2 tap smoke battery, run INSIDE a brfs test VM.
#
# Expects: /tmp/kmod (built brfs.ko), /tmp/brfsd, /tmp/brfs-devtest.
# Verifies: ring delivery of real fs events for every op class, lazy
# recursive dir flagging, cookie-paired renames, populated-dir import via
# the deferred taskqueue walk, DELROOT silence, unload-veto, and the
# unload-with-flags regression (2026-08-24 page-fault: stale flags +
# restored vector sent a flagged watchless vnode into inotify_log).
#
# usage: sudo sh tests/vm/tap-smoke.sh [TREE]
set -eu

TREE=${1:-/data/replicated}
KMOD=/tmp/kmod/brfs.ko
DEVTEST=/tmp/brfs-devtest
BRFSD=/tmp/brfsd
CONF=/tmp/tap-smoke.conf
LOG=/tmp/tap-smoke.log
ID=/tmp/tap-smoke.id
fails=0

note() { echo "== $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
ok() { echo "ok: $*"; }

have_event() { # op name-substr in the new log section
	sed -n "$(cat $ID),\$p" $LOG | grep -q "op=$1 " && \
	sed -n "$(cat $ID),\$p" $LOG | grep "op=$1 " | grep -q "$2"
}

# --- setup: fresh module, fresh tree, daemon running -------------------
pkill -x brfsd 2>/dev/null || true
sleep 1
kldstat -q -m brfs && kldunload brfs
rm -rf "$TREE" /tmp/tap-smoke-outside /tmp/tap-smoke-moved /tmp/tap-smoke-q.txt
mkdir -p "$TREE/pre/existing"
echo old > "$TREE/pre/existing/file.txt"
kldload "$KMOD"

cat > "$CONF" <<EOF
node_id = "smoke"
replicated_path = "$TREE"
state_dir = "/var/db/brfs"
peers = ["127.0.0.1:4590"]
EOF
: > "$LOG"
$BRFSD --config="$CONF" > "$LOG" 2>&1 &
sleep 2
grep -q "watch root registered" "$LOG" || { echo "FAIL: brfsd start"; exit 1; }

# Pre-existing tree flagged by the ADDROOT walk?  (File flags are set
# either by the walk or for free by cache_enter under an already-flagged
# parent — so verify functionally: a write to the pre-existing file must
# emit, and the dirs counter covers the directory flagging.)
[ "$(sysctl -n security.brfs.dirs_flagged)" -ge 3 ] || fail "ADDROOT walk dirs"

# --- op battery --------------------------------------------------------
echo 3 > $ID
cd "$TREE"
echo more >> pre/existing/file.txt        # pre-existing file, walk-flagged
sleep 0.2
have_event MODIFY "" || fail "MODIFY on pre-existing file (walk coverage)"
ok "ADDROOT walk flagged pre-existing tree"
touch newfile; echo data >> newfile
mkdir newdir; touch newdir/nested          # lazy upgrade of new dir
chmod 600 newfile
mv newfile renamed; rm renamed             # cookie-paired rename
mkdir -p /tmp/tap-smoke-outside/sub
touch /tmp/tap-smoke-outside/sub/deep.txt
mv /tmp/tap-smoke-outside "$TREE/imported" # populated dir renamed in
sleep 1                                    # let the taskqueue walk run
touch imported/sub/after.txt
sleep 1

have_event CREATE newfile    || fail "CREATE newfile"
have_event MODIFY ""         || fail "MODIFY"
have_event CREATE "newdir (dir)" || fail "CREATE dir"
have_event CREATE nested     || fail "CREATE in lazily-upgraded dir"
have_event ATTRIB ""         || fail "ATTRIB"
have_event MOVE_FROM newfile || fail "MOVE_FROM"
have_event MOVE_TO renamed   || fail "MOVE_TO"
have_event DELETE renamed    || fail "DELETE"
have_event MOVE_TO "imported (dir)" || fail "MOVE_TO imported dir"
have_event CREATE after.txt  || fail "CREATE after deferred subtree walk"

# cookie pairing: MOVE_FROM/MOVE_TO share one cookie
c1=$(grep "op=MOVE_FROM" $LOG | grep newfile | sed -e 's/.*cookie=\([^ ]*\).*/\1/' | tail -1)
c2=$(grep "op=MOVE_TO" $LOG | grep renamed | sed -e 's/.*cookie=\([^ ]*\).*/\1/' | tail -1)
[ -n "$c1" ] && [ "$c1" = "$c2" ] || fail "rename cookie pair ($c1 vs $c2)"
ok "op battery"

# --- move-out strip ------------------------------------------------------
# A dir or file renamed OUT of the watched tree must stop emitting
# (staging/quarantine locations share the patched vector; stale flags
# there would spam the ring).  Moving back in must restore coverage.
mkdir -p "$TREE/moveme/sub"
echo x > "$TREE/moveme/sub/f.txt"
echo q > "$TREE/quar.txt"
sleep 1
mv "$TREE/moveme" /tmp/tap-smoke-moved       # dir move-out
mv "$TREE/quar.txt" /tmp/tap-smoke-q.txt     # file move-out
sleep 2                                      # deferred unflag walk
wc -l < $LOG | tr -d ' ' > $ID               # marker: nothing may follow
echo y >> /tmp/tap-smoke-moved/sub/f.txt
touch /tmp/tap-smoke-moved/sub/quiet.txt
echo z >> /tmp/tap-smoke-q.txt
sleep 1
if sed -n "$(cat $ID),\$p" $LOG | grep -q "op="; then
	sed -n "$(cat $ID),\$p" $LOG | grep "op=" | head -5
	fail "events emitted from moved-out tree"
else
	ok "move-out strip (dir + file silent outside the tree)"
fi

mv /tmp/tap-smoke-moved "$TREE/back"
mv /tmp/tap-smoke-q.txt "$TREE/quar-back.txt"
sleep 2                                      # re-flag + deferred walk
wc -l < $LOG | tr -d ' ' > $ID
echo w >> "$TREE/back/sub/f.txt"
touch "$TREE/back/sub/again.txt"
echo v >> "$TREE/quar-back.txt"
sleep 1
# MODIFY self-events are NAMELESS: assert by count.  Two distinct files
# written = two MODIFY subjects (different fileids, no dedup collapse) —
# one re-flagged by the subtree walk (f.txt), one by the rename-time
# cache_enter (quar-back.txt).
modcount=$(sed -n "$(cat $ID),\$p" $LOG | grep -c "op=MODIFY " || true)
[ "$modcount" -ge 2 ] || fail "MODIFY coverage after move-back-in ($modcount < 2)"
have_event CREATE again.txt || fail "CREATE after move-back-in"
ok "move-back-in re-flag"

# --- DELROOT silence ----------------------------------------------------
pkill -x brfsd; sleep 1
$DEVTEST del "$TREE"
before=$(sysctl -n security.brfs.event_count)
touch "$TREE/after-delroot.txt"; sleep 0.3
after=$(sysctl -n security.brfs.event_count)
[ "$before" = "$after" ] || fail "events after DELROOT"
ok "DELROOT silence"

# --- unload veto + unload-with-flags regression -------------------------
# brfsd holds /dev/brfs open: kldunload must be vetoed (EBUSY).
$BRFSD --config="$CONF" >> "$LOG" 2>&1 &
sleep 2
if kldunload brfs 2>/dev/null; then
	fail "kldunload not vetoed while /dev/brfs open"
else
	ok "unload vetoed while daemon holds device"
fi
pkill -x brfsd; sleep 1
kldunload brfs
# The exact 2026-08-24 panic shape: the tree is still flagged, vectors
# are restored, no module loaded — do directory opens (fts in rm -rf).
rm -rf "$TREE"
echo survived unload+walkoff
kldload "$KMOD"
mkdir -p "$TREE"
$DEVTEST add "$TREE"
$DEVTEST stats | grep -q "roots=1" || fail "ADDROOT after reload"
ok "unload/reload lifecycle"

if [ "$fails" -eq 0 ]; then
	echo "TAP-SMOKE PASS"
else
	echo "TAP-SMOKE FAIL ($fails failures)"
	exit 1
fi
