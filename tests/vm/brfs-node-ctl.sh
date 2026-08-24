#!/bin/sh
# brfs-node-ctl.sh — guest-side helper for repl-tests.sh, deployed to
# /tmp on each node.  Exists so the host never nests quoting through
# ssh + doas.
set -u
TREE=/data/replicated
LOG=/tmp/brfsd.log
STATE=/var/db/brfs

case "${1:-}" in
start)
	doas pkill -x brfsd 2>/dev/null
	sleep 1
	doas rm -f "$LOG"
	doas sh -c "nohup /tmp/brfsd --config=/tmp/brfs.conf > $LOG 2>&1 &"
	;;
stop)
	doas pkill -x brfsd 2>/dev/null || true
	;;
kill9)
	doas pkill -9 -x brfsd 2>/dev/null || true
	;;
reset)
	doas pkill -x brfsd 2>/dev/null
	sleep 1
	doas rm -rf "$STATE"
	doas mkdir -p "$STATE"
	doas rm -rf "$TREE"
	doas mkdir -p "$TREE"
	doas chown admin "$TREE"
	;;
started)
	doas grep -q "watch root registered" "$LOG"
	;;
log)
	doas tail -"${2:-10}" "$LOG"
	;;
logcount) # logcount <pattern...> (fixed string, spaces ok)
	shift
	doas grep -cF "$*" "$LOG" || true
	;;
conflicts) # conflicts <substr...> -> count
	shift
	doas ls "$STATE/conflicts/" 2>/dev/null | grep -cF "$*" || true
	;;
*)
	echo "usage: $0 start|stop|kill9|reset|started|log [n]|logcount pat|conflicts pat" >&2
	exit 2
	;;
esac
