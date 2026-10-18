#!/bin/sh
# Source-restricted camera DNAT; no routes, interfaces, services or SNAT changes.
# Usage: sh camera-forwarding.sh check|apply|remove
# Persistent writes: 24 owned firewall redirects. Private backups stay in /tmp.
# Rerunnable. Exit: 0 success, 1 refused/failed operation, 2 invalid arguments.
set -eu
umask 077

suffixes='210 211 212 213 214 215'
owner='AnyToOmada camera forwarding v1'
alias_owner='AnyToOmada camera aliases v1'
guard_name='AnyToOmada camera aliases'
lock=/var/lock/ato-camera-aliases.lock
lock_owned=0
backup=
committed=0
owned_count=0

fail() { printf '%s\n' "$*" >&2; exit 1; }
optional_value() { uci -q get "$1" 2>/dev/null || true; }
usage() {
  printf '%s\n' 'Usage: sh camera-forwarding.sh check|apply|remove' \
    'Six VIPs: 10.30.30.210-215; only NVR .150 and NAS .100 sources.' \
    'Requires reserved/routed aliases; NAS backend ports must be verified separately.'
}

# One explicit mapping per logical camera. Two lenses share one physical source.
each_rule() {
  callback=$1
  for suffix in $suffixes; do
    index=$((suffix - 210))
    case "$suffix" in
      210) camera=10.30.30.2 ;;
      211) camera=10.30.30.4 ;;
      212|213) camera=10.30.30.10 ;;
      214|215) camera=10.30.30.13 ;;
    esac
    "$callback" "$suffix" nvr_https 10.20.0.150 443 192.168.100.100 "$((18443 + index))"
    "$callback" "$suffix" nvr_rtsp 10.20.0.150 554 192.168.100.100 "$((18554 + index))"
    "$callback" "$suffix" nas_rtsp 192.168.100.100 554 "$camera" 554
    "$callback" "$suffix" nas_native 192.168.100.100 37777 "$camera" 37777
  done
}

emit_manifest() {
  printf 'ato_fwd_%s_%s|%s|10.30.30.%s|%s|%s|%s\n' "$1" "$2" "$3" "$1" "$4" "$5" "$6"
}

check_owned_rule() {
  rule=ato_fwd_$1_$2
  expected_sections="$expected_sections $rule"
  if uci -q get "firewall.$rule" >/dev/null 2>&1; then
    [ "$(optional_value "firewall.$rule")" = redirect ] &&
      [ "$(optional_value "firewall.$rule.ato_owner")" = "$owner" ] &&
      [ "$(optional_value "firewall.$rule.name")" = "AnyToOmada $rule" ] ||
      fail "Unrecognized owned firewall section: $rule"
    owned_count=$((owned_count + 1))
  fi
}

# Return success if an address expression overlaps a VIP or cannot be understood.
# Unknown DNS names, ranges and inverted matches are refused rather than resolved.
overlaps_aliases() {
  awk -v value="$1" '
    function number(ip, parts, n, i, result) {
      n = split(ip, parts, "."); if (n != 4) return -1
      result = 0
      for (i = 1; i <= 4; i++) {
        if (parts[i] !~ /^[0-9]+$/ || parts[i] > 255) return -1
        result = result * 256 + parts[i]
      }
      return result
    }
    BEGIN {
      if (value == "") exit 0
      count = split(value, items, /[[:space:]]+/)
      for (item = 1; item <= count; item++) {
        fields = split(items[item], parts, "/")
        address = number(parts[1]); bits = fields == 1 ? 32 : parts[2]
        if (address < 0 || fields > 2 || bits !~ /^[0-9]+$/ || bits > 32) exit 0
        size = 2 ^ (32 - bits); network = int(address / size)
        for (last = 210; last <= 215; last++)
          if (int(number("10.30.30." last) / size) == network) exit 0
      }
      exit 1
    }
  '
}

check_firewall_ownership() {
  expected_sections=
  each_rule check_owned_rule
  inventory=$(uci show firewall) || fail 'Cannot inspect firewall section ownership.'
  sections=$(printf '%s\n' "$inventory" | awk -F= '$1 !~ /\.[^.]+\./ { sub(/^firewall\./, "", $1); print $1 " " $2 }')
  while read -r section kind; do
    case "$section" in
      ato_fwd_*)
        case " $expected_sections " in
          *" $section "*) continue ;;
          *) fail "Unknown forwarding section: $section" ;;
        esac
        ;;
    esac
    [ "$kind" = redirect ] || continue
    listen=$(optional_value "firewall.$section.src_dip")
    target=$(optional_value "firewall.$section.dest_ip")
    if overlaps_aliases "$listen" || { [ -n "$target" ] && overlaps_aliases "$target"; }; then
      fail "Unowned redirect may reference a camera VIP: $section"
    fi
  done <<EOF
$sections
EOF
}

verify_guard() {
  awk -v marker="$guard_name" '
    $1 == "chain" && $2 == "input" { inside = 1; next }
    inside && $1 == "}" { inside = 0 }
    inside && index($0, "comment \"!fw4: " marker "\"") {
      if ($0 !~ /ip daddr/ || $0 !~ /drop/ || $0 ~ /!=|saddr|iif|oif|l4proto|dport|sport/) exit 1
      for (i = 210; i <= 215; i++) if (index($0, "10.30.30." i)) covered[i] = 1
    }
    inside && /jump input_/ { for (i = 210; i <= 215; i++) if (!covered[i]) exit 1 }
    END { for (i = 210; i <= 215; i++) if (!covered[i]) exit 1 }
  '
}

verify_active_guard() {
  active_input=$(nft list chain inet fw4 input) || return 1
  printf '%s\n' "$active_input" | verify_guard
}

check_aliases() {
  [ "$(optional_value firewall.ato_cam_input.ato_owner)" = "$alias_owner" ] &&
    [ "$(optional_value firewall.ato_cam_input.name)" = "$guard_name" ] ||
    fail 'The owned camera-alias INPUT guard is missing.'
  addresses=$(ip -4 -o addr show) || fail 'Cannot inspect active aliases.'
  for suffix in $suffixes; do
    section=ato_cam_$suffix
    [ "$(optional_value "network.$section")" = interface ] &&
      [ "$(optional_value "network.$section.ato_owner")" = "$alias_owner" ] &&
      [ "$(optional_value "network.$section.device")" = @wan ] &&
      [ "$(optional_value "network.$section.proto")" = static ] &&
      [ "$(optional_value "network.$section.ipaddr")" = "10.30.30.$suffix" ] &&
      [ "$(optional_value "network.$section.netmask")" = 255.255.255.255 ] ||
      fail "Required owned alias is missing or changed: $section"
    printf '%s\n' "$addresses" | awk -v address="10.30.30.$suffix/32" \
      '$2 == "eth0.2" && $4 == address { found = 1 } END { exit !found }' ||
      fail "Required alias is not active on eth0.2: $section"
  done
  verify_active_guard || fail 'Active INPUT guard is missing, restricted or ordered too late.'
}

check_masquerade() {
  zones=$(printf '%s\n' "$inventory" | awk -F= '$2 == "zone" { sub(/^firewall\./, "", $1); print $1 }')
  wan_ok=0
  for zone in $zones; do
    [ "$(optional_value "firewall.$zone.name")" = wan ] || continue
    [ "$(optional_value "firewall.$zone.masq")" = 1 ] &&
      [ "$(optional_value "firewall.$zone.input")" = DROP ] &&
      [ -z "$(optional_value "firewall.$zone.masq_src")$(optional_value "firewall.$zone.masq_dest")" ] ||
      fail 'WAN must retain its existing unrestricted IPv4 masquerade and INPUT DROP.'
    wan_ok=1
  done
  [ "$wan_ok" = 1 ] || fail 'WAN firewall zone is missing.'
  active_snat=$(nft list chain inet fw4 srcnat_wan) || fail 'Cannot inspect active WAN masquerade.'
  printf '%s\n' "$active_snat" | awk '
    /meta nfproto ipv4/ && /masquerade/ && !/saddr|daddr/ { found = 1 }
    END { exit !found }
  ' || fail 'Expected active unrestricted IPv4 WAN masquerade is missing.'
}

stage_rule() {
  rule=ato_fwd_$1_$2
  uci -q delete "firewall.$rule" || true
  uci set "firewall.$rule=redirect"
  uci set "firewall.$rule.ato_owner=$owner"
  uci set "firewall.$rule.name=AnyToOmada $rule"
  uci set "firewall.$rule.family=ipv4"
  uci set "firewall.$rule.src=wan"
  uci set "firewall.$rule.src_ip=$3"
  uci set "firewall.$rule.src_dip=10.30.30.$1"
  uci set "firewall.$rule.src_dport=$4"
  uci set "firewall.$rule.dest=wan"
  uci set "firewall.$rule.dest_ip=$5"
  uci set "firewall.$rule.dest_port=$6"
  uci set "firewall.$rule.proto=tcp"
  uci set "firewall.$rule.target=DNAT"
  uci set "firewall.$rule.reflection=0"
}

remove_rule() { uci -q delete "firewall.ato_fwd_$1_$2" || true; }

verify_redirects() {
  awk -F'|' -v wanted="$2" '
    NR == FNR { source[$1] = $2; vip[$1] = $3; port[$1] = $4; target[$1] = $5 ":" $6; next }
    $1 ~ /^[[:space:]]*chain dstnat_wan[[:space:]]*\{/ { inside = 1; next }
    inside && $1 ~ /^[[:space:]]*\}/ { inside = 0 }
    /comment "!fw4: AnyToOmada ato_fwd_/ {
      count++; if (!inside || wanted == 0) exit 1
      line = $0; gsub(/dnat ip to |dnat ip |dnat to /, "dnat ", line)
      matched = 0
      for (name in source) {
        if (!index(line, "comment \"!fw4: AnyToOmada " name "\"")) continue
        if (seen[name]++ || line ~ /!=|\{/ ||
            !index(line, "ip saddr " source[name] " ") ||
            !index(line, "ip daddr " vip[name] " ") ||
            !index(line, "tcp dport " port[name] " ") ||
            !index(line, "dnat " target[name] " ")) exit 1
        matched = 1
      }
      if (!matched) exit 1
    }
    END { if (count != wanted) exit 1 }
  ' "$backup/manifest" "$1"
}

reload_firewall() {
  /etc/init.d/firewall reload || return 1
  fw4 check || return 1
}

on_exit() {
  code=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ "$code" -ne 0 ] && [ -n "$backup" ]; then
    rollback_ok=1
    uci revert firewall || rollback_ok=0
    if [ "$committed" = 1 ]; then
      cp -p "$backup/firewall" /etc/config/firewall || rollback_ok=0
      reload_firewall || rollback_ok=0
    fi
    if [ "$rollback_ok" = 1 ]; then
      printf 'Change failed; previous firewall restored. Backup: %s\n' "$backup" >&2
    else
      printf 'Firewall rollback incomplete; inspect private backup: %s\n' "$backup" >&2
    fi
  fi
  [ "$lock_owned" = 0 ] || rmdir "$lock" || code=1
  exit "$code"
}

action=${1:-check}
[ "$#" -le 1 ] || { usage >&2; exit 2; }
case "$action" in check|apply|remove) ;; -h|--help) usage; exit 0 ;; *) usage >&2; exit 2 ;; esac
for command in uci ubus jsonfilter fw4 nft ip awk grep cp df wc; do
  command -v "$command" >/dev/null || fail "Required installed command is missing: $command"
done
[ -x /etc/init.d/firewall ] || fail 'firewall4 service is unavailable.'
for package in network firewall wireless; do
  [ -z "$(uci changes "$package")" ] || fail "Save or discard pending $package edits first."
done
status=$(ubus call network.interface.wan status)
[ "$(printf '%s' "$status" | jsonfilter -e '@["ipv4-address"][0].address')" = 10.20.0.2 ] &&
  [ "$(printf '%s' "$status" | jsonfilter -e '@.l3_device')" = eth0.2 ] ||
  fail 'Expected existing wired WAN 10.20.0.2 on eth0.2.'
check_firewall_ownership
if [ "$action" != remove ]; then
  check_aliases
  check_masquerade
fi
fw4 check
firewall_bytes=$(wc -c < /etc/config/firewall)
free_kib=$(df -Pk /overlay | awk 'NR == 2 { print $4 }')
case "$free_kib" in ''|*[!0-9]*) fail 'Cannot determine writable flash space.' ;; esac
required_kib=$(((firewall_bytes + 65536 + 1023) / 1024))
printf 'Owned redirects: %s/24. Free overlay: %s KiB; required reserve: %s KiB.\n' \
  "$owned_count" "$free_kib" "$required_kib"
if [ "$action" = check ]; then
  printf '%s\n' 'Prerequisites passed; DHCP reservations, routes, NAS ports and end-to-end traffic are not checked.'
  exit 0
fi
[ "$free_kib" -ge "$required_kib" ] || fail 'Insufficient flash reserve for firewall replacement and rollback.'
mkdir "$lock" 2>/dev/null || fail 'Another alias/forwarding operation is running, or its lock remains.'
lock_owned=1
trap on_exit EXIT
trap 'exit 130' HUP INT
trap 'exit 143' TERM
for package in network firewall wireless; do
  [ -z "$(uci changes "$package")" ] || fail 'Configuration edits appeared while acquiring the lock.'
done
backup=$(mktemp -d /tmp/ato-camera-forwarding-before.XXXXXX)
cp -p /etc/config/firewall "$backup/firewall"
each_rule emit_manifest > "$backup/manifest"
if [ "$action" = apply ]; then
  each_rule stage_rule
  wanted=24
else
  each_rule remove_rule
  wanted=0
fi
fw4 check
fw4 print > "$backup/candidate.nft"
verify_redirects "$backup/candidate.nft" "$wanted" || fail 'Rendered DNAT rules do not match the exact mapping.'
if [ "$action" = apply ]; then
  verify_guard < "$backup/candidate.nft" || fail 'Rendered alias INPUT protection changed.'
fi
committed=1
uci commit firewall
reload_firewall
nft list chain inet fw4 dstnat_wan > "$backup/active-dnat.nft"
verify_redirects "$backup/active-dnat.nft" "$wanted" || fail 'Active DNAT rules do not match the exact mapping.'
if [ "$action" = apply ]; then
  verify_active_guard || fail 'Active alias INPUT protection changed.'
fi
after_bytes=$(wc -c < /etc/config/firewall)
printf 'Camera forwarding %s completed. UCI text growth: %s bytes. Backup: %s\n' \
  "$action" "$((after_bytes - firewall_bytes))" "$backup"
printf '%s\n' 'Existing connections are not terminated. Keep private backups off-router before reboot.'
