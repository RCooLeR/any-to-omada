#!/bin/sh
# Manage six reserved virtual-camera aliases on the existing Mango WAN.
# Usage: sh camera-aliases.sh check|apply|remove
# Writes only owned UCI sections; backups and transaction state stay in /tmp.
# Does not add routes, forwarding, packages or services. Reruns are supported.
# Exit: 0 success, 1 failed check/change, 2 usage error.
set -eu
umask 077

suffixes='210 211 212 213 214 215'
owner='AnyToOmada camera aliases v1'
guard=ato_cam_input
guard_name='AnyToOmada camera aliases'
transaction_table=ato_camera_alias_transaction
lock=/var/lock/ato-camera-aliases.lock
backup=
lock_owned=0
transaction_owned=0
network_committed=0
firewall_committed=0
previous_up=
configured_count=0

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' 'Usage: sh camera-aliases.sh check|apply|remove' \
    'Addresses: 10.30.30.210-215/32 on @wan; router-service access is blocked.' \
    'Upstream /32 routes and reserved addresses must be arranged separately.'
}

optional_value() {
  uci -q get "$1" 2>/dev/null || true
}

address_present() {
  printf '%s\n' "$addresses" | grep -Fq "inet $1/"
}

read_addresses() {
  addresses=$(ip -4 -o addr show) || return 1
}

# The guard must be in global INPUT, before any zone jump to GL admin rules.
# Checking both rendered and installed rules catches an omitted/disabled rule.
verify_guard() {
  awk -v marker="$guard_name" '
    $1 == "chain" && $2 == "input" { inside = 1; next }
    inside && $1 == "}" { inside = 0 }
    inside && index($0, "comment \"!fw4: " marker "\"") {
      if ($0 !~ /ip daddr/ || $0 !~ /drop/ || $0 ~ /!=/ ||
          $0 ~ /saddr|iif|oif|l4proto|dport|sport/) exit 1
      for (i = 210; i <= 215; i++)
        if (index($0, "10.30.30." i)) covered[i] = 1
    }
    inside && /jump input_/ {
      for (i = 210; i <= 215; i++) if (!covered[i]) exit 1
    }
    END {
      for (i = 210; i <= 215; i++) if (!covered[i]) exit 1
    }
  '
}

verify_active_guard() {
  active_input=$(nft list chain inet fw4 input) || return 1
  printf '%s\n' "$active_input" | verify_guard
}

check_owned_sections() {
  read_addresses || fail 'Cannot inspect current IPv4 addresses.'
  for suffix in $suffixes; do
    section=ato_cam_$suffix
    address=10.30.30.$suffix
    if uci -q get "network.$section" >/dev/null 2>&1; then
      [ "$(optional_value "network.$section")" = interface ] &&
        [ "$(optional_value "network.$section.ato_owner")" = "$owner" ] &&
        [ "$(optional_value "network.$section.device")" = @wan ] &&
        [ "$(optional_value "network.$section.proto")" = static ] &&
        [ "$(optional_value "network.$section.ipaddr")" = "$address" ] &&
        [ "$(optional_value "network.$section.netmask")" = 255.255.255.255 ] ||
        fail "Unrecognized or changed network section: $section"
      configured_count=$((configured_count + 1))
      if status=$(ubus call "network.interface.$section" status 2>/dev/null); then
        up=$(printf '%s' "$status" | jsonfilter -e '@.up')
        [ "$up" != true ] || previous_up="$previous_up $section"
      fi
    elif address_present "$address"; then
      fail "$address is already configured outside its owned interface."
    fi
  done
  if uci -q get "firewall.$guard" >/dev/null 2>&1; then
    [ "$(optional_value "firewall.$guard")" = rule ] &&
      [ "$(optional_value "firewall.$guard.ato_owner")" = "$owner" ] &&
      [ "$(optional_value "firewall.$guard.name")" = "$guard_name" ] ||
      fail "Unrecognized firewall section: $guard"
  elif [ "$configured_count" -ne 0 ]; then
    fail 'Owned aliases exist without their persistent guard; repair before proceeding.'
  fi
  if [ "$configured_count" -ne 0 ]; then
    verify_active_guard || fail 'Existing aliases are not protected by the expected active guard.'
  fi
}

stage_guard() {
  uci -q delete "firewall.$guard" || true
  uci set "firewall.$guard=rule"
  uci set "firewall.$guard.ato_owner=$owner"
  uci set "firewall.$guard.name=$guard_name"
  uci set "firewall.$guard.family=ipv4"
  uci set "firewall.$guard.src=*"
  uci set "firewall.$guard.proto=all"
  uci set "firewall.$guard.target=DROP"
  for suffix in $suffixes; do
    uci add_list "firewall.$guard.dest_ip=10.30.30.$suffix"
  done
  uci reorder "firewall.$guard=0"
}

stage_aliases() {
  for suffix in $suffixes; do
    section=ato_cam_$suffix
    uci -q delete "network.$section" || true
    uci set "network.$section=interface"
    uci set "network.$section.ato_owner=$owner"
    uci set "network.$section.device=@wan"
    uci set "network.$section.proto=static"
    uci set "network.$section.ipaddr=10.30.30.$suffix"
    uci set "network.$section.netmask=255.255.255.255"
    uci set "network.$section.defaultroute=0"
    uci set "network.$section.peerdns=0"
  done
}

validate_staged_guard() {
  fw4 check
  fw4 print > "$backup/candidate.nft"
  verify_guard < "$backup/candidate.nft" || fail 'Rendered INPUT guard is missing or too late.'
}

reload_firewall() {
  /etc/init.d/firewall reload || return 1
  fw4 check || return 1
}

bring_up() {
  timeout 15 ifup -w "$1" || return 1
  attempt=0
  while [ "$attempt" -lt 10 ]; do
    status=$(ubus call "network.interface.$1" status) || return 1
    actual=$(printf '%s' "$status" | jsonfilter -e '@["ipv4-address"][0].address') || return 1
    [ "$actual" != "$2" ] || return 0
    attempt=$((attempt + 1))
    sleep 1
  done
  printf 'Alias did not become active: %s\n' "$1" >&2
  return 1
}

restore_previous_state() {
  rollback_ok=1
  uci revert network || rollback_ok=0
  uci revert firewall || rollback_ok=0
  if [ "$network_committed" = 1 ]; then
    for suffix in $suffixes; do
      # Only these six owned interfaces can be interrupted during rollback.
      ifdown "ato_cam_$suffix" >/dev/null 2>&1 || true
    done
    cp -p "$backup/network" /etc/config/network || rollback_ok=0
    ubus call network reload >/dev/null || rollback_ok=0
    for section in $previous_up; do
      suffix=${section#ato_cam_}
      bring_up "$section" "10.30.30.$suffix" || rollback_ok=0
    done
    if read_addresses; then
      for suffix in $suffixes; do
        if ! uci -q get "network.ato_cam_$suffix" >/dev/null 2>&1 &&
          address_present "10.30.30.$suffix"; then
          rollback_ok=0
        fi
      done
    else
      rollback_ok=0
    fi
  fi
  # Never remove the persistent/temporary guard after an incomplete network restore.
  if [ "$rollback_ok" = 1 ] && [ "$firewall_committed" = 1 ]; then
    cp -p "$backup/firewall" /etc/config/firewall || rollback_ok=0
    reload_firewall || rollback_ok=0
    if [ "$configured_count" -ne 0 ]; then
      verify_active_guard || rollback_ok=0
    fi
  fi
  [ "$rollback_ok" = 1 ]
}

on_exit() {
  code=$?
  trap - EXIT HUP INT TERM
  set +e
  safe_to_release=1
  if [ "$code" -ne 0 ] && [ -n "$backup" ]; then
    if restore_previous_state; then
      printf 'Change failed; previous configuration restored. Backup: %s\n' "$backup" >&2
    else
      safe_to_release=0
      printf 'Rollback incomplete. Keep guard %s; inspect backup %s.\n' \
        "$transaction_table" "$backup" >&2
    fi
  fi
  if [ "$transaction_owned" = 1 ] && [ "$safe_to_release" = 1 ]; then
    nft delete table inet "$transaction_table" || code=1
  fi
  [ "$lock_owned" = 0 ] || rmdir "$lock" || code=1
  exit "$code"
}

action=${1:-check}
[ "$#" -le 1 ] || { usage >&2; exit 2; }
case "$action" in
  check|apply|remove) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
for command in uci ubus jsonfilter fw4 nft ip ifup ifdown timeout awk grep cp df wc; do
  command -v "$command" >/dev/null || fail "Required installed command is missing: $command"
done
[ -x /etc/init.d/firewall ] || fail 'firewall4 service is unavailable.'
[ -z "$(uci changes network)" ] || fail 'Save or discard pending network edits first.'
[ -z "$(uci changes firewall)" ] || fail 'Save or discard pending firewall edits first.'
[ -z "$(uci changes wireless)" ] || fail 'Save or discard pending wireless edits first.'
status=$(ubus call network.interface.wan status)
wan_address=$(printf '%s' "$status" | jsonfilter -e '@["ipv4-address"][0].address')
wan_device=$(printf '%s' "$status" | jsonfilter -e '@.l3_device')
[ "$wan_address" = 10.20.0.2 ] && [ "$wan_device" = eth0.2 ] ||
  fail 'Expected existing wired WAN 10.20.0.2 on eth0.2.'
check_owned_sections
fw4 check
network_bytes=$(wc -c < /etc/config/network)
firewall_bytes=$(wc -c < /etc/config/firewall)
free_kib=$(df -Pk /overlay | awk 'NR == 2 { print $4 }')
case "$free_kib" in ''|*[!0-9]*) fail 'Cannot determine writable flash space.' ;; esac
required_kib=$(((network_bytes + firewall_bytes + 32768 + 1023) / 1024))
printf 'Owned aliases: %s/6. Free overlay: %s KiB; required reserve: %s KiB.\n' \
  "$configured_count" "$free_kib" "$required_kib"
if [ "$action" = check ]; then
  printf '%s\n' 'Prerequisites passed; address allocation, upstream routes and reachability are not checked.'
  exit 0
fi
[ "$free_kib" -ge "$required_kib" ] || fail 'Insufficient flash reserve for UCI replacement and rollback.'
if nft list table inet "$transaction_table" >/dev/null 2>&1; then
  fail "Transaction guard already exists: $transaction_table; inspect prior recovery first."
fi
mkdir "$lock" 2>/dev/null || fail 'Another alias operation is running, or its lock remains.'
lock_owned=1
trap on_exit EXIT
trap 'exit 130' HUP INT
trap 'exit 143' TERM
[ -z "$(uci changes network)" ] && [ -z "$(uci changes firewall)" ] &&
  [ -z "$(uci changes wireless)" ] || fail 'Configuration edits appeared while acquiring the lock.'
backup=$(mktemp -d /tmp/ato-camera-aliases-before.XXXXXX)
cp -p /etc/config/network "$backup/network"
cp -p /etc/config/firewall "$backup/firewall"

# A separate early INPUT hook protects established flows and all transaction gaps.
nft -f - <<EOF
table inet $transaction_table {
  chain input {
    type filter hook input priority -10; policy accept;
    ip daddr { 10.30.30.210, 10.30.30.211, 10.30.30.212, 10.30.30.213, 10.30.30.214, 10.30.30.215 } counter drop
  }
}
EOF
transaction_owned=1

if [ "$action" = apply ]; then
  stage_guard
  stage_aliases
  validate_staged_guard
  firewall_committed=1
  uci commit firewall
  reload_firewall
  verify_active_guard || fail 'Persistent INPUT guard did not load.'
  network_committed=1
  uci commit network
  for suffix in $suffixes; do
    bring_up "ato_cam_$suffix" "10.30.30.$suffix"
  done
  verify_active_guard || fail 'INPUT guard changed during alias activation.'
else
  # Keep the installed guard until netifd has removed all owned addresses.
  # Mark the runtime change before ifdown: even a partial failure needs restoration.
  network_committed=1
  for suffix in $suffixes; do
    section=ato_cam_$suffix
    if uci -q get "network.$section" >/dev/null 2>&1; then
      ifdown "$section"
      uci delete "network.$section"
    fi
  done
  uci commit network
  ubus call network reload >/dev/null
  read_addresses || fail 'Cannot verify that owned addresses were removed.'
  for suffix in $suffixes; do
    if address_present "10.30.30.$suffix"; then
      fail "Address 10.30.30.$suffix remains active; retaining protection."
    fi
  done
  uci -q delete "firewall.$guard" || true
  fw4 check
  firewall_committed=1
  uci commit firewall
  reload_firewall
fi

after_network_bytes=$(wc -c < /etc/config/network)
after_firewall_bytes=$(wc -c < /etc/config/firewall)
growth=$((after_network_bytes + after_firewall_bytes - network_bytes - firewall_bytes))
printf 'Camera aliases %s completed. UCI text growth: %s bytes. Backup: %s\n' \
  "$action" "$growth" "$backup"
printf '%s\n' 'This installer does not manage camera forwarding. Copy the private backup off Mango before reboot; /tmp is volatile.'
