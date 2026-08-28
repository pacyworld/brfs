#!/bin/sh
# t-unmount.sh — gap #16 forced-unmount freeze, on brfs-a only (uses the
# testz scratch zpool; the main replication tree on /data is left alone
# and the main daemon is restored at the end).
#
# A dedicated brfsd watches a scratch dataset.  Force-unmounting it must
# FREEZE the daemon (deferred rescans, no tombstoning of the "vanished"
# tree); a restart while unmounted must freeze at startup; remounting
# restores the fsid and the daemon resumes cleanly.
#
# usage: sh tests/vm/t-unmount.sh
set -u
A=10.66.0.11
CTLM=/tmp/brfs-ssh-ctl
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60 -o ControlPath=$CTLM-$A"
fails=0

ssh -MNf -o BatchMode=yes -o ConnectTimeout=60 \
	-o ControlPath=$CTLM-$A -o ControlPersist=30m admin@$A 2>/dev/null || true
trap 'ssh -O exit -o ControlPath=$CTLM-$A admin@$A 2>/dev/null' EXIT

note() { echo "== $*"; }
ok()   { echo "ok: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
R()   { $SSH admin@$A "$1"; }
TULOG() { R "doas grep -cF \"$1\" /tmp/brfsd-tu.log || true" | tr -d ' \r\n'; }

TU_start() { # start the scratch daemon (nohup like the main rig)
	R "doas pkill -x brfsd 2>/dev/null; sleep 1; doas rm -f /tmp/brfsd-tu.log; doas sh -c 'nohup /tmp/brfsd --config=/tmp/brfs-tu.conf > /tmp/brfsd-tu.log 2>&1 &'"
	sleep 4
	TULOG "watch root registered"
}

cleanup() {
	R "doas pkill -x brfsd 2>/dev/null; sleep 1; doas zfs destroy -f testz/brfstu 2>/dev/null; doas rm -f /tmp/brfs-tu.conf /tmp/brfs-tu.psk /tmp/brfsd-tu.log; sh /tmp/brfs-node-ctl.sh start" >/dev/null 2>&1
}

note "setup: scratch dataset + dedicated brfsd (alt psk/port, no mesh peer)"
R "doas zfs destroy -rf testz/brfstu 2>/dev/null; doas zfs create testz/brfstu && doas mkdir -p /testz/brfstu/tree /testz/brfstu/state && doas chown -R admin /testz/brfstu/tree" || { echo "FATAL: scratch setup failed"; exit 1; }
R "printf 'tu-psk-not-the-mesh-key\n' > /tmp/brfs-tu.psk && doas chown root:wheel /tmp/brfs-tu.psk && doas chmod 600 /tmp/brfs-tu.psk"
R "printf '%s\n' 'node_id = \"a-tu\"' 'replicated_path = \"/testz/brfstu/tree\"' 'state_dir = \"/testz/brfstu/state\"' 'listen = \"127.0.0.1:4591\"' 'peers = [\"127.0.0.1:4599\"]' 'psk_file = \"/tmp/brfs-tu.psk\"' 'primary = true' > /tmp/brfs-tu.conf"

R "sh /tmp/brfs-node-ctl.sh stop"
[ "$(TU_start)" = "1" ] || { fail "scratch brfsd start"; R "doas cat /tmp/brfsd-tu.log"; cleanup; exit 1; }
R "echo one > /testz/brfstu/tree/tu1.txt && echo two > /testz/brfstu/tree/tu2.txt"
sleep 3
TULOG "announce tu1.txt" | grep -q "^[1-9]" && ok "scratch tree announcing" || fail "no announce from scratch daemon"

note "runtime: force-unmount, trigger resync, expect frozen scan"
R "doas zfs unmount -f testz/brfstu"
R "doas /tmp/brfsctl resync" >/dev/null
sleep 4
TULOG "rescan deferred, tombstones frozen" | grep -q "^[1-9]" \
	&& ok "runtime rescan frozen after umount -f" \
	|| { fail "runtime freeze did not trigger"; R "doas tail -12 /tmp/brfsd-tu.log"; }
# The tree's records must NOT be tombstoned.
R "doas /tmp/brfsctl status" | grep -q ", 0 tombstones" \
	&& ok "no tombstones while frozen" || fail "phantom tombstones while frozen"

note "startup while unmounted: tree path absent -> fail fast, no storm"
R "doas pkill -x brfsd; sleep 1; doas rm -f /tmp/brfsd-tu.log; doas sh -c 'nohup /tmp/brfsd --config=/tmp/brfs-tu.conf > /tmp/brfsd-tu.log 2>&1 &'"
sleep 4
if R "pgrep -x brfsd >/dev/null"; then
	fail "daemon running with the tree path absent"
	R "doas tail -8 /tmp/brfsd-tu.log"
else
	TULOG "ADDROOT" | grep -q "^[1-9]" \
		&& ok "fail-fast on absent tree (no watch, no tombstones)" \
		|| { fail "unexpected startup failure mode"; R "doas tail -8 /tmp/brfsd-tu.log"; }
fi

note "remount: fsid is mount-stable -> restart resumes cleanly"
R "doas zfs mount testz/brfstu"
sleep 1
[ "$(TU_start)" = "1" ] || fail "restart after remount"
R "doas /tmp/brfsctl status" | grep -q "fs: ok" \
	&& ok "unfrozen after remount+restart" || fail "still frozen after remount"
R "echo three > /testz/brfstu/tree/tu3.txt"
sleep 3
TULOG "announce tu3.txt" | grep -q "^[1-9]" \
	&& ok "announcing resumed after remount" || fail "no announce after remount"

cleanup
sleep 3
R "sh /tmp/brfs-node-ctl.sh started" && ok "main brfsd restored" || fail "main brfsd restore"

if [ "$fails" -eq 0 ]; then
	echo "UNMOUNT PASS"
else
	echo "UNMOUNT FAIL ($fails failures)"
	exit 1
fi
