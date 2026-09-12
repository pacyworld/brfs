#!/bin/sh
# brfs-conf-key.sh <key> <value|-> — set or delete a scalar key in
# /tmp/brfs.conf (in place, preserving the rest).  Guest-side helper for
# t-shaping.sh; exists so the host never nests quoting through ssh+doas.
set -u

key=${1:?key}
val=${2:--}
CONF=/tmp/brfs.conf
tmp=$CONF.new
grep -v "^$key " $CONF > $tmp
[ "$val" != "-" ] && echo "$key = $val" >> $tmp
mv $tmp $CONF
