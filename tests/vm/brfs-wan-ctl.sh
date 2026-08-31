#!/bin/sh
# brfs-wan-ctl.sh — guest-side WAN impairment helper for t21-t24-wan.sh,
# deployed to /tmp on each node.  Exists so the host never nests quoting
# through ssh + doas.
#
# Mechanism: dummynet pipes scoped to peer-pair traffic (PLAN.md's
# sanctioned fallback; there is no ng_netem on FreeBSD — never was — so
# the guest vtnet-path option would have been ng_pipe(4)).
# One OUTBOUND pipe per peer, matching all IP traffic between this node
# and the peer's IP.  ssh (host 10.66.0.1 -> guest) never matches a rule,
# so impairment can never lock out the control channel.
#
# ipfw is loaded with the default-to-accept tunable pre-set via kenv:
# loading ipfw.ko cold installs rule 65535 "deny ip from any to any"
# which instantly locks out ssh (rig-proven 2026-08-29 — brfs-a needed a
# bhyve reboot to recover).  kenv + kldload yields "65535 allow" instead.
#
#   init                          load ipfw+dummynet safely (idempotent)
#   set <pipe> <peer-ip> <delay-ms|-> <plr|-> <bw|->
#                                 (re)configure the outbound pipe to a peer;
#                                 all-neutral params remove the rule
#   clear                         delete all impairment rules (pipes stay
#                                 configured but unreferenced = inert)
#   show                          ipfw rules + pipe configs (debug)
#
# Mechanism notes (rig-proven 2026-08-29): FreeBSD has no ng_netem (that
# name is Linux's tc qdisc; it never existed in base — the netgraph link
# emulator is ng_pipe(4)).  dummynet delay/plr/bw all work correctly
# with TLS+KTLS traffic once brfsd's nonblocking SSL_write handling was
# fixed (partial-write modes + stable bounce buffer); before that fix,
# ANY delayed link killed TLS bulk transfers.  ng_pipe (L2 inline on
# vtnet0) was validated as an alternative but abandoned: it impairs the
# ssh control channel and its 100Hz tick inflates configured delays.
set -u

case "${1:-}" in
init)
	doas kenv net.inet.ip.fw.default_to_accept=1
	kldstat -q -m ipfw 2>/dev/null || doas kldload ipfw
	kldstat -q -m dummynet 2>/dev/null || doas kldload dummynet
	doas ipfw list 65535 | grep -q "allow ip from any to any" || {
		echo "wan-ctl: FATAL: ipfw default rule is not allow" >&2
		exit 1
	}
	;;
set)
	pipe=$2; peer=$3; delay=$4; plr=$5; bw=$6
	rule=$((1000 + pipe))
	doas ipfw delete "$rule" 2>/dev/null
	# dummynet config MERGES: unspecified parameters keep their previous
	# values.  Always emit all three with explicit neutral values
	# (delay 0ms / plr 0 / bw 0 = unlimited) so a re-set is deterministic.
	[ "$delay" = "-" ] && delay=0
	[ "$plr" = "-" ] && plr=0
	[ "$bw" = "-" ] && bw=0
	if [ "$delay" = "0" ] && [ "$plr" = "0" ] && [ "$bw" = "0" ]; then
		exit 0   # all-neutral = unimpair: rule stays deleted
	fi
	doas ipfw add "$rule" pipe "$pipe" ip from me to "$peer" out
	doas ipfw pipe "$pipe" config delay "${delay}ms" plr "$plr" bw "$bw"
	;;
clear)
	for r in 1011 1012 1013; do doas ipfw delete "$r" 2>/dev/null; done
	;;
show)
	doas ipfw list
	doas ipfw pipe list
	;;
*)
	echo "usage: $0 init | set <pipe> <peer-ip> <delay|-> <plr|-> <bw|-> | clear | show" >&2
	exit 2
	;;
esac
