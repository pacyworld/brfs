#!/bin/sh
# t8-only.sh — targeted rerun of the T8 flow (kill -9 mid-FETCH) with
# wall-clock timing, for bisecting fetch-path performance changes without
# a full repl-tests.sh run.
set -u
A=10.66.0.11; B=10.66.0.12; C=10.66.0.13
TREE=/data/replicated
CTLM=/tmp/brfs-ssh-ctl
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=60 -o ControlPath=$CTLM-%h"
for ip in $A $B $C; do
	ssh -MNf -o BatchMode=yes -o ConnectTimeout=60 \
		-o ControlPath=$CTLM-$ip -o ControlPersist=15m admin@$ip
done
trap 'for ip in $A $B $C; do ssh -O exit -o ControlPath=$CTLM-$ip admin@$ip 2>/dev/null; done' EXIT

R() { $SSH admin@"$1" "$2"; }
CTL() { $SSH admin@"$1" "sh /tmp/brfs-node-ctl.sh $2"; }
sha_on() { R "$1" "sha256 -q $2 2>/dev/null" | tr -d ' \r\n'; }

echo "== reset"
for ip in $A $B $C; do CTL "$ip" reset; done
for ip in $A $B $C; do CTL "$ip" start; done
sleep 8

R $A "echo warm > $TREE/warm.txt"
sleep 3

echo "== T8: 200MB create on A, kill -9 B mid-fetch, restart B"
t0=$(date +%s)
R $A "dd if=/dev/urandom of=$TREE/big.bin bs=1m count=200 2>/dev/null"
echo "dd took $(($(date +%s) - t0))s"
want=$(sha_on $A $TREE/big.bin)
sleep 1
CTL $B kill9
sleep 1
CTL $B start
t1=$(date +%s)
i=0
ok=0
while [ $i -lt 720 ]; do
	got=$(sha_on $B $TREE/big.bin)
	[ "$got" = "$want" ] && { ok=1; break; }
	sleep 0.5; i=$((i + 1))
done
if [ $ok -eq 1 ]; then
	echo "T8: B converged in $(($(date +%s) - t1))s (after restart)"
else
	echo "T8: TIMEOUT ($(($(date +%s) - t1))s)"
fi
