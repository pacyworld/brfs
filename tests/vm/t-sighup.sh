#!/bin/sh
# t-sighup.sh — gap #19 SIGHUP runtime reconfig + metrics surface smoke.
#
# Under nohup(1) the daemon inherits SIGHUP=SIG_IGN; EVFILT_SIGNAL never
# reports an ignored signal, so the daemon explicitly resets the
# disposition.  This test proves the reload path end-to-end under the
# rig's actual nohup supervision.
#
# usage: sh tests/vm/t-sighup.sh
set -u
A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
CTLM=/tmp/brfs-ssh-ctl
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60 -o ControlPath=$CTLM-%h"
fails=0

for ip in $A $B $C; do
	ssh -MNf -o BatchMode=yes -o ConnectTimeout=60 \
		-o ControlPath=$CTLM-$ip -o ControlPersist=30m admin@$ip 2>/dev/null || true
done
trap 'for ip in $A $B $C; do ssh -O exit -o ControlPath=$CTLM-$ip admin@$ip 2>/dev/null; done' EXIT

note() { echo "== $*"; }
ok()   { echo "ok: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
R()   { $SSH admin@"$1" "$2"; }
CTL() { $SSH admin@"$1" "sh /tmp/brfs-node-ctl.sh $2"; }

note "setup: clean trees, daemons running"
for ip in $A $B $C; do CTL $ip reset; done
for ip in $A $B $C; do CTL $ip start; done
sleep 8
for ip in $A $B $C; do
	CTL $ip started || { fail "brfsd start on $ip"; CTL $ip log 8; }
done

note "SIGHUP reload (nohup-supervised)"
R $A "doas cp /tmp/brfs.conf /tmp/brfs.conf.sighup-bak && doas sh -c 'echo rate_limit = 12345 >> /tmp/brfs.conf'"
R $A "doas pkill -HUP -x brfsd"
sleep 3
R $A "pgrep -x brfsd >/dev/null" || fail "brfsd died on SIGHUP"
CTL $A "logcount SIGHUP: reloading config" | grep -q "^[1-9]" \
	&& ok "reload logged" || { fail "no reload in log"; CTL $A log 10; }
CTL $A "logcount rate_limit now 12345" | grep -q "^[1-9]" \
	&& ok "rate_limit change applied" || fail "rate_limit reload line missing"
R $A "doas mv /tmp/brfs.conf.sighup-bak /tmp/brfs.conf"
R $A "doas pkill -HUP -x brfsd"
sleep 3

note "replication still works after reloads"
R $A "echo sighup > $TREE/sighup.txt"
want=$(R $A "sha256 -q $TREE/sighup.txt" | tr -d ' \r\n')
i=0
while [ $i -lt 60 ]; do
	got=$(R $B "sha256 -q $TREE/sighup.txt 2>/dev/null" | tr -d ' \r\n')
	[ "$got" = "$want" ] && break
	sleep 0.5; i=$((i + 1))
done
[ "$got" = "$want" ] && ok "post-reload replication" || fail "post-reload replication"

note "metrics surface"
m=$(R $A "doas /tmp/brfsctl metrics")
echo "$m" | grep -q "^brfs_kmod_events " || fail "metrics: kmod counters missing"
echo "$m" | grep -q 'brfs_records{node="a",state="live"}' || fail "metrics: records missing"
echo "$m" | grep -q "^brfs_member_vector_lag" || fail "metrics: vector lag missing"
echo "$m" | grep -q 'brfs_massdelete_latched{node="a"} 0' || fail "metrics: guard gauge missing"
[ $fails -eq 0 ] && ok "metrics exposition"

if [ "$fails" -eq 0 ]; then
	echo "SIGHUP PASS"
else
	echo "SIGHUP FAIL ($fails failures)"
	exit 1
fi
