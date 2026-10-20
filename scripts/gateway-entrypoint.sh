#!/bin/sh
set -eu

host=${HOST_PROXY_HOST:?HOST_PROXY_HOST is required}
port=${HOST_PROXY_PORT:?HOST_PROXY_PORT is required}
case "$port" in ''|*[!0-9]*) echo 'Invalid host proxy port' >&2; exit 64;; esac
test "$port" -ge 1 && test "$port" -le 65535
case "$host" in ''|*[!a-zA-Z0-9._-]*) echo 'Invalid host proxy host' >&2; exit 64;; esac
# The trusted init is the only process permitted to resolve this one host name.
# It does not resolve any internet destinations.
ip=$(getent ahostsv4 "$host" | awk 'NR==1 {print $1}')
case "$ip" in ''|*[!0-9.]*) echo 'Cannot resolve host proxy IPv4 address' >&2; exit 69;; esac

# These affect this new gateway's network namespace only, never the host.
iptables -w -P INPUT DROP
iptables -w -P FORWARD DROP
iptables -w -P OUTPUT DROP
iptables -w -F INPUT
iptables -w -F FORWARD
iptables -w -F OUTPUT
iptables -w -A INPUT -i lo -j ACCEPT
iptables -w -A OUTPUT -o lo -j ACCEPT
iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w -A OUTPUT -p tcp -d "$ip" --dport "$port" -j ACCEPT
ip6tables -w -P INPUT DROP
ip6tables -w -P FORWARD DROP
ip6tables -w -P OUTPUT DROP
ip6tables -w -F INPUT
ip6tables -w -F FORWARD
ip6tables -w -F OUTPUT

mkdir -p /run/claude-ipc
chown 0:0 /run/claude-ipc
chmod 0755 /run/claude-ipc
chown 1000:1000 /run/claude-ipc
export UPSTREAM_PROXY_ADDR="$ip:$port"
unset HOST_PROXY_HOST HOST_PROXY_PORT HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
exec setpriv --reuid=1000 --regid=1000 --clear-groups \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  /usr/local/bin/claude-egress
