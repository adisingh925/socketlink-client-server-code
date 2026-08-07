#!/usr/bin/env bash
# provision_vm.sh — prepare a bare Ubuntu VM to run the standalone server natively
# (no Docker). Run as root on the VM:
#     bash provision_vm.sh
#
# Installs only the RUNTIME libraries the binary links against; the binary itself
# is copied in separately (scp). Build-from-source is only needed if the VM's
# distro differs from the build host.
set -eu

echo "=== OS ==="
grep PRETTY /etc/os-release

echo "=== installing runtime libraries ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    libssl3t64 zlib1g liblmdb0 libtbb12 libmysqlclient21 ca-certificates \
    || apt-get install -y -qq --no-install-recommends \
       libssl3 zlib1g liblmdb0 libtbb12 libmysqlclient21 ca-certificates

echo "=== raising limits for high connection counts ==="
# fd limit: one per connection, plus headroom
cat > /etc/security/limits.d/99-socketlink.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

# network tuning for many concurrent sockets and fan-out
cat > /etc/sysctl.d/99-socketlink.conf <<'EOF'
# accept queue: a fast ramp can offer thousands of connections per second
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
# per-socket buffers stay small; the server also caps SO_SNDBUF itself, which is
# what keeps kernel `sock` memory bounded under fan-out
net.ipv4.tcp_wmem = 4096 8192 262144
net.ipv4.tcp_rmem = 4096 8192 262144
# recycle TIME_WAIT quickly during repeated benchmark runs
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
# widen the ephemeral range (matters when the load client runs here too)
net.ipv4.ip_local_port_range = 1024 65535
EOF
sysctl -p /etc/sysctl.d/99-socketlink.conf >/dev/null

mkdir -p /opt/socketlink/messages_db

echo "=== done ==="
echo "fd limit now: $(ulimit -n) (new logins get 1048576)"
