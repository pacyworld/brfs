#!/bin/sh
# provision-brfs-node.sh <a|b|c> — host-side provisioning of a BrFS test
# VM zvol before first boot. Mounts the guest root, installs rc.conf,
# admin user + ssh key, disables ttyu0 getty (100% CPU spin lesson),
# copies a trimmed /usr/src for in-guest kmod builds.
set -eu

case "${1:-}" in
a) HOST=brfs-a; IP=10.66.0.11 ;;
b) HOST=brfs-b; IP=10.66.0.12 ;;
c) HOST=brfs-c; IP=10.66.0.13 ;;
*) echo "usage: $0 {a|b|c}" >&2; exit 1 ;;
esac

ZVOL=/dev/zvol/vault/VMs/${HOST}
ROOTPART=${ZVOL}p4
MNT=/tmp/mnt-${HOST}

PUBKEY=$(cat /home/admin/.ssh/id_ed25519.pub)

mkdir -p "$MNT"
mount -o rw "$ROOTPART" "$MNT"
trap 'umount "$MNT" 2>/dev/null || true' EXIT

# --- rc.conf ---
cat > "$MNT/etc/rc.conf" <<EOF
hostname="${HOST}"
ifconfig_vtnet0="inet ${IP}/24"
defaultrouter="10.66.0.1"
sshd_enable="YES"
growfs_enable="YES"
sendmail_enable="NONE"
sendmail_submit_enable="NO"
sendmail_outbound_enable="NO"
sendmail_msp_queue_enable="NO"
dumpdev="NO"
EOF

# --- ttyu0 getty OFF (stray serial input spins getty/login at 100% CPU) ---
sed -i '' -e 's|^\(ttyu0.*\)on  *ifexists|\1off ifexists|' "$MNT/etc/ttys"
grep -q 'ttyu0.*off' "$MNT/etc/ttys" || {
	sed -i '' -e 's|^ttyu0.*|ttyu0 "/usr/libexec/getty 3wire" vt100 off ifexists secure|' "$MNT/etc/ttys"
}

# --- admin user (wheel), locked password, ssh key only ---
chroot "$MNT" /usr/sbin/pw useradd -n admin -u 1001 -c "Admin" \
	-s /bin/sh -m -G wheel -w no 2>/dev/null || true
mkdir -p "$MNT/home/admin/.ssh"
echo "$PUBKEY" > "$MNT/home/admin/.ssh/authorized_keys"
chmod 700 "$MNT/home/admin/.ssh"
chmod 600 "$MNT/home/admin/.ssh/authorized_keys"
chroot "$MNT" /usr/sbin/chown -R 1001:1001 /home/admin/.ssh

# --- sshd: key auth only ---
cat >> "$MNT/etc/ssh/sshd_config" <<EOF
PasswordAuthentication no
PermitRootLogin no
EOF

# --- resolver: host NAT path ---
cat > "$MNT/etc/resolv.conf" <<EOF
nameserver 10.66.0.1
EOF

# --- trimmed /usr/src for in-guest kmod builds (sys only; the guest base
# system provides /usr/share/mk, which is what bsd.kmod.mk needs) ---
if [ ! -d "$MNT/usr/src/sys" ]; then
	mkdir -p "$MNT/usr/src"
	cp -a /usr/src/sys "$MNT/usr/src/"
fi

sync
umount "$MNT"
trap - EXIT
rmdir "$MNT"
echo "provisioned ${HOST} (${IP})"
