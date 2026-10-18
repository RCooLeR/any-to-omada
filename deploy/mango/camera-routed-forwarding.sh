#!/bin/sh
# Camera VIPs: restricted historical or unrestricted HTTPS/RTSP frontend mappings.
# Usage: check|apply|remove|render or check-lan|migrate-lan|apply-lan|remove-lan|render-lan
# Writes only owned camera UCI and the owned nft table/rules. /tmp backups.
# No ifup, netifd reload, firewall reload, packages or conntrack flush. Rerunnable.
# Exit 0 success, 1 refused/failed operation, 2 invalid arguments.
set -eu
umask 077

owner='AnyToOmada routed camera forwarding v1'
table=ato_routed_camera
prefix='AnyToOmada routed '
section_prefix=ato_rte
suffixes='210 211 212 213 214 215'
first_suffix=210
last_suffix=215
vip_prefix=10.30.30
vip_list=
vip_words=
alias_owner='AnyToOmada LAN camera aliases v1'
mode=routed
migration=0
rule_policy=restricted
policy_migration=0
expected_count=26
network_committed=0
network_hash=
added_addresses=
removed_addresses=
alias_count=0
alias_names=
lock=/var/lock/ato-camera-aliases.lock
backup=
locked=0
committed=0
applied=0
had_table=0
owned_count=0
committed_hash=

fail() { printf '%s\n' "$*" >&2; exit 1; }
value() { uci -q get "$1" 2>/dev/null || true; }
usage() { printf '%s\n' 'Usage: camera-routed-forwarding.sh check|apply|remove|render' '       camera-routed-forwarding.sh check-lan|migrate-lan|apply-lan|remove-lan|render-lan' '       camera-routed-forwarding.sh check-open-lan|migrate-open-lan|apply-open-lan|remove-open-lan|render-open-lan' '       camera-routed-forwarding.sh check-additional-lan|apply-additional-lan|remove-additional-lan|render-additional-lan' 'Routed: reserved 10.30.30.210-215 with upstream /32 routes. LAN: reserved 10.20.0.210-215.' 'Additional LAN: reserved 10.20.0.216-221, independent owned table and aliases.'; }

select_policy() {
  rule_policy=$1
  expected_count=26
  [ "$rule_policy" != open ] || expected_count=14
}

select_vips() {
  vip_prefix=$1
  vip_words=
  vip_list=
  for suffix in $suffixes; do
    vip_words="${vip_words}${vip_words:+ }$vip_prefix.$suffix"
    vip_list="${vip_list}${vip_list:+, }$vip_prefix.$suffix"
  done
}
select_vips "$vip_prefix"

each_rule() {
  callback=$1
  for suffix in $suffixes; do
    index=$((suffix - 210))
    case "$suffix" in
      210) camera=10.30.30.2 ;; 211) camera=10.30.30.4 ;;
      212|213) camera=10.30.30.10 ;; 214|215) camera=10.30.30.13 ;;
      *) [ "$rule_policy" = open ] || fail 'Additional VIPs support only the open LAN profile.' ;;
    esac
    client=10.20.0.150
    [ "$rule_policy" != open ] || client=
    "$callback" "${section_prefix}_${suffix}_nvr_https" "$client" "$vip_prefix.$suffix" 443 192.168.100.100 "$((18443 + index))"
    "$callback" "${section_prefix}_${suffix}_nvr_rtsp" "$client" "$vip_prefix.$suffix" 554 192.168.100.100 "$((18554 + index))"
    if [ "$rule_policy" = restricted ]; then
      "$callback" "${section_prefix}_${suffix}_nas_rtsp" 192.168.100.100 "$vip_prefix.$suffix" 554 "$camera" 554
      "$callback" "${section_prefix}_${suffix}_nas_native" 192.168.100.100 "$vip_prefix.$suffix" 37777 "$camera" 37777
    fi
  done
}

nft_rule() {
  printf 'iifname "eth0.2" '
  [ -z "$2" ] || printf 'ip saddr %s ' "$2"
  printf 'ip daddr %s tcp dport %s counter dnat ip to %s:%s comment "%s%s"\n' "$3" "$4" "$5" "$6" "$prefix" "$1"
}

render_table() {
  printf 'table inet %s {\ncomment "%s"\nchain prerouting {\ntype nat hook prerouting priority -110; policy accept;\n' "$table" "$owner"
  each_rule nft_rule
  printf '}\n'
  for chain in input forward; do
    printf 'chain %s {\ntype filter hook %s priority -10; policy accept;\nip daddr { %s } counter drop comment "%s%s"\n}\n' "$chain" "$chain" "$vip_list" "$prefix" "$chain"
  done
  printf '}\n'
}

expected_rule() {
  printf '%s|prerouting|' "$1"
  nft_rule "$@"
}

# Normalize only presentation details that nft/firewall4 change. Unknown clauses,
# filters, chains, handles, duplicate markers and extra owned-table objects refuse.
inspect_rules() {
  awk -F'|' -v mode="$2" -v table="$table" -v owner="$owner" -v prefix="$prefix" \
    -v removals="$backup/fw4-delete.nft" -v restore="$backup/fw4-restore.nft" '
    function norm(s) {
      gsub(/counter packets [0-9]+ bytes [0-9]+/, "counter", s)
      sub(/[[:space:]]*# handle [0-9]+[[:space:]]*$/, "", s)
      gsub(/dnat ip to |dnat ip |dnat to /, "dnat ", s)
      gsub(/priority dstnat[[:space:]]*-[[:space:]]*10/, "priority -110", s)
      gsub(/priority filter[[:space:]]*-[[:space:]]*10/, "priority -10", s)
      gsub(/[[:space:]]/, "", s)
      return s
    }
    NR == FNR { wanted[$1] = norm($3); expected_chain[$1] = $2; expected_count++; next }
    {
      raw=$0; compact=norm(raw)
      if (mode == "table" && compact == "comment\"" norm(owner) "\"") { owners++; next }
      if ($1 ~ /^[[:space:]]*chain /) { chain=$2; split(raw, words, /[[:space:]]+/); sub(/^[[:space:]]*chain[[:space:]]+/, "", raw); split(raw, words, /[[:space:]]+/); chain=words[1] }
      marker=index($0, "comment \"" (mode == "fw4" ? "!fw4: " : "") prefix)
      if (marker) {
        name=substr($0, marker + length("comment \"") + length(mode == "fw4" ? "!fw4: " : "") + length(prefix)); sub(/".*/, "", name)
        if (!(name in wanted) || seen[name]++) exit 1
        line=$0
        if (mode == "fw4") {
          if (chain != (expected_chain[name] == "prerouting" ? "dstnat_wan" : expected_chain[name])) exit 1
          sub(/!fw4: /, "", line)
          if (expected_chain[name] == "prerouting") sub(/ip (saddr|daddr)/, "iifname \"eth0.2\" &", line)
        } else if (chain != expected_chain[name]) exit 1
        if (norm(line) != wanted[name]) exit 1
        count++
        if (mode == "fw4") {
          if ($0 !~ /# handle [0-9]+[[:space:]]*$/) exit 1
          handle=$0; sub(/.*# handle /, "", handle); gsub(/[[:space:]]/, "", handle)
          print "delete rule inet fw4 " chain " handle " handle > removals
          line=$0; sub(/[[:space:]]*# handle [0-9]+[[:space:]]*$/, "", line)
          print "insert rule inet fw4 " chain " " line > restore
        }
        next
      }
      if (mode != "table") next
      if (compact == "" || compact == "}") next
      if (compact == "tableinet" table "{") { tables++; next }
      if (compact == "chainprerouting{" || compact == "chaininput{" || compact == "chainforward{") { chains++; next }
      if ((chain == "prerouting" && compact == "typenathookpreroutingpriority-110;policyaccept;") ||
          ((chain == "input" || chain == "forward") && compact == "typefilterhook" chain "priority-10;policyaccept;")) {
        if (hook_seen[chain]++) exit 1
        hooks++; next
      }
      exit 1
    }
    END {
      if (mode == "table" && (count != expected_count || tables != 1 || owners != 1 || chains != 3 || hooks != 3)) exit 1
      if (mode == "fw4" && count != 0 && count != expected_count) exit 1
    }
  ' "$backup/expected" "$1"
}

assert_value() { [ "$(value "firewall.$rule.$1")" = "$2" ] || fail "Changed owned setting: $rule.$1"; }
check_rule() {
  rule=$1
  names="$names $rule"
  [ -n "$(value "firewall.$rule")" ] || return 0
  [ "$(value "firewall.$rule")" = redirect ] || fail "Changed owned section: $rule"
  assert_value ato_owner "$owner"; assert_value name "$prefix$rule"
  assert_value family ipv4; assert_value src wan; assert_value dest wan
  assert_value src_ip "$2"; assert_value src_dip "$3"; assert_value src_dport "$4"
  assert_value dest_ip "$5"; assert_value dest_port "$6"
  assert_value proto tcp; assert_value target DNAT; assert_value reflection 0
  options=14
  [ -n "$2" ] || options=13
  [ "$(uci show "firewall.$rule" | wc -l)" -eq "$options" ] || fail "Extra owned options: $rule"
  owned_count=$((owned_count + 1))
}

overlaps() {
  awk -v value="$1" -v first="$first_suffix" -v last="$last_suffix" '
    function number(ip, a, i, n, v) { n=split(ip,a,"."); if(n!=4)return -1; for(i=1;i<=4;i++){if(a[i]!~/^[0-9]+$/||a[i]>255)return -1;v=v*256+a[i]}return v }
    BEGIN { if(value=="")exit 0; n=split(value,items,/[[:space:]]+/); for(i=1;i<=n;i++){f=split(items[i],p,"/");a=number(p[1]);b=f==1?32:p[2];if(a<0||f>2||b!~/^[0-9]+$/||b>32)exit 0;s=2^(32-b);for(j=first;j<=last;j++)if(int(a/s)==int(number("10.30.30."j)/s)||int(a/s)==int(number("10.20.0."j)/s))exit 0}exit 1 }
  '
}

check_ownership() {
  names=
  each_rule check_rule
  for chain in input forward; do
    rule=${section_prefix}_$chain
    names="$names $rule"
    [ -n "$(value "firewall.$rule")" ] || continue
    [ "$(value "firewall.$rule")" = rule ] || fail "Changed guard type: $rule"
    assert_value ato_owner "$owner"; assert_value name "$prefix$chain"
    assert_value family ipv4; assert_value src '*'; assert_value proto all; assert_value target DROP
    assert_value dest_ip "$vip_words"
    expected_options=8
    if [ "$chain" = forward ]; then assert_value dest '*'; expected_options=9; fi
    [ "$(uci show "firewall.$rule" | wc -l)" -eq "$expected_options" ] || fail "Extra guard options: $rule"
    owned_count=$((owned_count + 1))
  done
  [ "$owned_count" = 0 ] || [ "$owned_count" = "$expected_count" ] || fail 'Partial camera configuration; inspect before repair.'
  inventory=$(uci show firewall)
  sections=$(printf '%s\n' "$inventory" | awk -F= '$1 !~ /\.[^.]+\./ {sub(/^firewall\./,"",$1);print $1 " " $2}')
  while read -r section kind; do
    case "$section" in
      ato_cam_*|ato_fwd_*) fail 'Alias-mode camera configuration exists; do not mix installers.' ;;
      "$section_prefix"_*) case " $names " in *" $section "*) continue ;; *) fail "Unknown routed section: $section" ;; esac ;;
    esac
    [ "$kind" = redirect ] || continue
    listen=$(value "firewall.$section.src_dip"); target=$(value "firewall.$section.dest_ip")
    if overlaps "$listen" || { [ -n "$target" ] && overlaps "$target"; }; then fail "Unowned redirect overlaps camera VIPs: $section"; fi
  done <<EOF
$sections
EOF
}

stage_rule() {
  rule=$1
  uci -q delete "firewall.$rule" || true
  uci set "firewall.$rule=redirect"
  for pair in "ato_owner=$owner" "name=$prefix$rule" family=ipv4 src=wan dest=wan "src_dip=$3" "src_dport=$4" "dest_ip=$5" "dest_port=$6" proto=tcp target=DNAT reflection=0; do uci set "firewall.$rule.$pair"; done
  [ -z "$2" ] || uci set "firewall.$rule.src_ip=$2"
}

stage_configuration() {
  if [ "$rule_policy" = open ]; then
    for suffix in $suffixes; do
      uci -q delete "firewall.${section_prefix}_${suffix}_nas_rtsp" || true
      uci -q delete "firewall.${section_prefix}_${suffix}_nas_native" || true
    done
  fi
  each_rule stage_rule
  for chain in input forward; do
    rule=${section_prefix}_$chain
    uci -q delete "firewall.$rule" || true
    uci set "firewall.$rule=rule"
    for pair in "ato_owner=$owner" "name=$prefix$chain" family=ipv4 'src=*' proto=all target=DROP; do uci set "firewall.$rule.$pair"; done
    [ "$chain" != forward ] || uci set "firewall.$rule.dest=*"
    for suffix in $suffixes; do uci add_list "firewall.$rule.dest_ip=$vip_prefix.$suffix"; done
    uci reorder "firewall.$rule=0"
  done
}

# Persist normal netifd aliases for the next natural reload/reboot. Immediate
# activation uses ip only; invoking ifup would reload the whole GL network.
check_aliases() {
  alias_count=0
  alias_names=
  addresses=$(ip -4 -o addr show)
  for suffix in $suffixes; do
    section=${section_prefix}_alias_$suffix
    alias_names="$alias_names $section"
    if [ -n "$(value "network.$section")" ]; then
      [ "$mode" = lan ] || fail 'LAN aliases require the explicit -lan commands.'
      [ "$(value "network.$section")" = interface ] || fail "Changed alias type: $section"
      for pair in "ato_owner=$alias_owner" device=@wan proto=static "ipaddr=10.20.0.$suffix" netmask=255.255.255.255 defaultroute=0 peerdns=0; do
        key=${pair%%=*}; expected=${pair#*=}
        [ "$(value "network.$section.$key")" = "$expected" ] || fail "Changed alias setting: $section.$key"
      done
      [ "$(uci show "network.$section" | wc -l)" -eq 8 ] || fail "Extra alias options: $section"
      alias_count=$((alias_count + 1))
      if [ "$action" = remove ] && ubus call "network.interface.$section" status >/dev/null 2>&1; then
        fail "Netifd has loaded $section; removal needs a separate maintenance procedure."
      fi
    elif printf '%s\n' "$addresses" | grep -Fq "inet 10.20.0.$suffix/"; then
      fail "Unowned local address: 10.20.0.$suffix"
    fi
    matches=$(printf '%s\n' "$addresses" | awk -v ip="10.20.0.$suffix" '$3 == "inet" && index($4,ip "/")==1 {print $2 " " $4}')
    [ -z "$matches" ] || [ "$matches" = "eth0.2 10.20.0.$suffix/32" ] || fail "Unexpected address device/prefix: 10.20.0.$suffix"
    [ -z "$(value "network.ato_cam_$suffix")" ] || fail 'Historical alias configuration exists.'
    if printf '%s\n' "$addresses" | grep -Fq "inet 10.30.30.$suffix/"; then fail 'Old routed VIPs must not be local aliases.'; fi
  done
  for section in $(uci show network | awk -F= '$1 !~ /\.[^.]+\./ {sub(/^network\./,"",$1);print $1}'); do
    case "$section" in "$section_prefix"_alias_*) case " $alias_names " in *" $section "*) ;; *) fail "Unknown LAN alias: $section" ;; esac ;; esac
  done
  [ "$alias_count" = 0 ] || [ "$alias_count" = 6 ] || fail 'Partial LAN alias configuration; inspect before repair.'
  [ "$alias_count" = 0 ] || [ "$vip_prefix" = 10.20.0 ] || fail 'LAN aliases and routed guards do not match.'
}

stage_aliases() {
  for suffix in $suffixes; do
    section=${section_prefix}_alias_$suffix
    if [ "$action" = remove ]; then uci -q delete "network.$section" || true; continue; fi
    uci set "network.$section=interface"
    for pair in "ato_owner=$alias_owner" device=@wan proto=static "ipaddr=10.20.0.$suffix" netmask=255.255.255.255 defaultroute=0 peerdns=0; do uci set "network.$section.$pair"; done
  done
}

on_exit() {
  code=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ "$code" -ne 0 ] && [ -n "$backup" ]; then
    recovered=1
    for section in $names; do uci -q revert "firewall.$section" || true; done
    for section in $alias_names; do uci -q revert "network.$section" || true; done
    # New local addresses must disappear before their guards can be rolled back.
    # If deletion fails, keep the new guards/configuration for manual recovery.
    for address in $added_addresses; do ip addr del "$address/32" dev eth0.2 || recovered=0; done
    if [ "$committed" = 1 ] && [ "$recovered" = 1 ]; then
      current_hash=$(sha256sum /etc/config/firewall | awk '{print $1}')
      if [ -z "$committed_hash" ] || [ "$current_hash" != "$committed_hash" ]; then
        recovered=0
        printf '%s\n' 'Firewall changed concurrently; refusing to overwrite newer configuration.' >&2
      fi
    fi
    if [ "$network_committed" = 1 ] && [ "$recovered" = 1 ]; then
      if [ -z "$network_hash" ] || [ "$(sha256sum /etc/config/network | awk '{print $1}')" != "$network_hash" ]; then
        recovered=0
        printf '%s\n' 'Network configuration changed concurrently; refusing to overwrite it.' >&2
      fi
    fi
    # Validate both fingerprints before restoring either file. Restore aliases
    # before old guards when undoing an install; restore guards first when
    # undoing a removal. A failed copy never leaves persisted unguarded aliases.
    if [ "$action" != remove ] && [ "$network_committed" = 1 ] && [ "$recovered" = 1 ]; then
      cp -p "$backup/network" /etc/config/network || recovered=0
    fi
    if [ "$committed" = 1 ] && [ "$recovered" = 1 ]; then
      cp -p "$backup/firewall" /etc/config/firewall || recovered=0
    fi
    if [ "$action" = remove ] && [ "$network_committed" = 1 ] && [ "$recovered" = 1 ]; then
      cp -p "$backup/network" /etc/config/network || recovered=0
    fi
    if [ "$applied" = 1 ] && [ "$recovered" = 1 ]; then nft -f "$backup/rollback.nft" || recovered=0; fi
    if [ "$recovered" = 1 ]; then
      for address in $removed_addresses; do ip addr add "$address/32" dev eth0.2 || recovered=0; done
    fi
    if [ "$recovered" = 1 ]; then printf 'Previous camera configuration restored. Backup: %s\n' "$backup" >&2
    else printf 'Recovery incomplete; inspect private backup: %s\n' "$backup" >&2; fi
  fi
  [ "$locked" = 0 ] || rmdir "$lock" || code=1
  exit "$code"
}

action=${1:-check}
[ "$#" -le 1 ] || { usage >&2; exit 2; }
case "$action" in
  check-additional-lan|apply-additional-lan|remove-additional-lan|render-additional-lan)
    owner='AnyToOmada additional camera forwarding v1'
    table=ato_additional_camera
    prefix='AnyToOmada additional '
    section_prefix=ato_add
    alias_owner='AnyToOmada additional LAN camera aliases v1'
    suffixes='216 217 218 219 220 221'
    first_suffix=216; last_suffix=221
    mode=lan; select_policy open; action=${action%-additional-lan} ;;
  check-open-lan|apply-open-lan|remove-open-lan|render-open-lan)
    mode=lan; select_policy open; action=${action%-open-lan} ;;
  migrate-open-lan) mode=lan; select_policy open; policy_migration=1; action=apply ;;
  check-lan|apply-lan|remove-lan|render-lan) mode=lan; action=${action%-lan} ;;
  migrate-lan) mode=lan; migration=1; action=apply ;;
esac
[ "$mode" != lan ] || select_vips 10.20.0
case "$action" in check|apply|remove) ;; render) render_table; exit 0 ;; -h|--help) usage; exit 0 ;; *) usage >&2; exit 2 ;; esac
if [ "$migration" = 1 ]; then
  [ "${ATO_OLD_ROUTES_RETIRED:-}" = yes ] || fail 'Retire the old exact-owned gateway routes first, then set ATO_OLD_ROUTES_RETIRED=yes.'
fi
desired_prefix=$vip_prefix
desired_policy=$rule_policy
for command in uci ubus jsonfilter nft fw4 ip awk grep cp df wc flock sha256sum; do command -v "$command" >/dev/null || fail "Missing command: $command"; done
for package in network firewall wireless; do [ -z "$(uci changes "$package")" ] || fail "Save or discard pending $package edits first."; done
status=$(ubus call network.interface.wan status)
[ "$(printf '%s' "$status" | jsonfilter -e '@["ipv4-address"][0].address')" = 10.20.0.2 ] && [ "$(printf '%s' "$status" | jsonfilter -e '@.l3_device')" = eth0.2 ] || fail 'Expected WAN 10.20.0.2 on eth0.2.'
existing_vip=$(value "firewall.${section_prefix}_${first_suffix}_nvr_https.src_dip")
case "$existing_vip" in
  '') existing_prefix=$desired_prefix ;;
  "10.30.30.$first_suffix") existing_prefix=10.30.30 ;;
  "10.20.0.$first_suffix") existing_prefix=10.20.0 ;;
  *) fail 'Unrecognized installed VIP addresses.' ;;
esac
existing_policy=$desired_policy
if [ -n "$existing_vip" ]; then
  case "$(value "firewall.${section_prefix}_${first_suffix}_nvr_https.src_ip")" in
    10.20.0.150) existing_policy=restricted ;;
    '') existing_policy=open ;;
    *) fail 'Unrecognized installed source policy.' ;;
  esac
fi
if [ "$existing_policy" != "$desired_policy" ]; then
  [ "$desired_policy" = open ] && { [ "$policy_migration" = 1 ] || [ "$action" = check ]; } || fail 'Use migrate-open-lan explicitly; do not silently change the installed source policy.'
fi
if [ "$desired_policy" = open ]; then
  [ "$existing_prefix" = 10.20.0 ] || fail 'Migrate to LAN VIPs before changing their source policy.'
fi
if [ "$existing_prefix" != "$desired_prefix" ]; then
  [ "$mode" = lan ] && { [ "$migration" = 1 ] || [ "$action" = check ]; } || fail 'Use explicit migrate-lan to replace routed VIPs; reverse migration is unsupported.'
fi
select_vips "$existing_prefix"
select_policy "$existing_policy"
check_aliases
check_ownership
[ "$alias_count" = 0 ] || [ "$owned_count" = "$expected_count" ] || fail 'LAN aliases require complete persistent guards.'
if [ "$existing_prefix" = 10.20.0 ] && [ "$owned_count" = "$expected_count" ]; then
  [ "$alias_count" = 6 ] || fail 'Installed LAN forwarding has no complete owned aliases.'
fi
zones=$(printf '%s\n' "$inventory" | awk -F= '$2=="zone"{sub(/^firewall\./,"",$1);print $1}')
wan_ok=0
for zone in $zones; do
  [ "$(value "firewall.$zone.name")" = wan ] || continue
  [ "$(value "firewall.$zone.masq")" = 1 ] && [ "$(value "firewall.$zone.input")" = DROP ] && [ -z "$(value "firewall.$zone.masq_src")$(value "firewall.$zone.masq_dest")" ] || fail 'Expected existing unrestricted WAN masquerade and INPUT DROP.'
  wan_ok=1
done
[ "$wan_ok" = 1 ] || fail 'WAN zone is missing.'
nft list chain inet fw4 srcnat_wan | grep -q 'meta nfproto ipv4 masquerade' || fail 'Active WAN masquerade missing.'
nft list chain inet fw4 forward_wan | grep -q 'ct status dnat accept' || fail 'Active WAN forwarding must accept DNAT.'
free_kib=$(df -Pk /overlay | awk 'NR==2{print $4}')
firewall_bytes=$(wc -c < /etc/config/firewall)
required_kib=$(((firewall_bytes + 65536 + 1023) / 1024))
if [ "$mode" = lan ]; then
  required_kib=$((required_kib + ($(wc -c < /etc/config/network) + 4096 + 1023) / 1024))
fi
case "$free_kib" in ''|*[!0-9]*) fail 'Cannot determine free flash.' ;; esac
[ "$free_kib" -ge "$required_kib" ] || fail 'Insufficient writable flash reserve.'

mkdir "$lock" 2>/dev/null || fail 'Another camera operation or leftover lock exists.'
locked=1
trap on_exit EXIT
trap 'exit 130' HUP INT
trap 'exit 143' TERM
# Cooperate with normal firewall4 reloads while reading handles and applying a batch.
exec 9>/var/run/fw4.lock
flock -x 9
for package in network firewall wireless; do [ -z "$(uci changes "$package")" ] || fail 'Pending edits appeared while acquiring locks.'; done
owned_count=0
check_aliases
check_ownership
installed_expected=$expected_count
backup=$(mktemp -d /tmp/ato-camera-routed-before.XXXXXX)
cp -p /etc/config/firewall "$backup/firewall"
before_hash=$(sha256sum "$backup/firewall" | awk '{print $1}')
if [ "$mode" = lan ]; then
  cp -p /etc/config/network "$backup/network"
  network_before_hash=$(sha256sum "$backup/network" | awk '{print $1}')
fi
each_rule expected_rule > "$backup/expected"
for chain in input forward; do printf '%s|%s|ip daddr { %s } counter drop comment "%s%s"\n' "$chain" "$chain" "$vip_list" "$prefix" "$chain" >> "$backup/expected"; done
: > "$backup/fw4-delete.nft"
: > "$backup/fw4-restore.nft"
nft -a list table inet fw4 > "$backup/fw4-before.nft"
inspect_rules "$backup/fw4-before.nft" fw4 || fail 'Active generated camera rules differ or have incomplete ownership.'
if nft list table inet "$table" > "$backup/table-before.nft" 2>/dev/null; then
  had_table=1
  [ "$owned_count" = "$expected_count" ] || fail 'Owned live table has no complete persistent configuration.'
  inspect_rules "$backup/table-before.nft" table || fail 'Unrecognized live camera table; refusing takeover.'
fi
[ "$owned_count" = "$expected_count" ] || [ ! -s "$backup/fw4-delete.nft" ] || fail 'Generated live rules have no persistent owner.'
# A live alias is safe only when either the exact custom table or all generated
# guards/rules are present. Refuse to repair an unguarded address implicitly.
if [ "$alias_count" = 6 ] && [ "$had_table" = 0 ] && [ ! -s "$backup/fw4-delete.nft" ]; then
  fail 'Existing aliases have no verified active guards.'
fi
select_vips "$desired_prefix"
select_policy "$desired_policy"
render_table > "$backup/table-desired.nft"
: > "$backup/change.nft"
[ "$had_table" = 0 ] || printf 'delete table inet %s\n' "$table" >> "$backup/change.nft"
cat "$backup/fw4-delete.nft" >> "$backup/change.nft"
[ "$action" = remove ] || cat "$backup/table-desired.nft" >> "$backup/change.nft"
nft -c -f "$backup/change.nft"
if [ "$action" = check ]; then
  printf 'Camera prerequisites passed: %s/%s installed sections, %s/6 aliases; %s KiB free, %s KiB reserve; target %s.%s-%s, %s policy (%s sections).\n' "$owned_count" "$installed_expected" "$alias_count" "$free_kib" "$required_kib" "$desired_prefix" "$first_suffix" "$last_suffix" "$desired_policy" "$expected_count"
  printf '%s\n' 'Address reservation, old-route retirement, NAS ports and permitted-client traffic remain separate checks.'
  printf 'Private backup: %s\n' "$backup"
  exit 0
fi
if [ "$action" = apply ]; then stage_configuration
else for section in $names; do uci -q delete "firewall.$section" || true; done; fi
[ "$mode" != lan ] || stage_aliases
# Compare the desired generated rules with the desired VIPs, keeping the earlier
# live snapshot and its exact handles exclusively for deletion/rollback.
each_rule expected_rule > "$backup/expected"
for chain in input forward; do printf '%s|%s|ip daddr { %s } counter drop comment "%s%s"\n' "$chain" "$chain" "$vip_list" "$prefix" "$chain" >> "$backup/expected"; done
fw4 check
fw4 print > "$backup/candidate.nft"
# Require exactly the expected generated rules; add synthetic handles for this
# read-only comparison (the removal list from the live snapshot is retained).
cp "$backup/fw4-delete.nft" "$backup/delete-saved.nft"
cp "$backup/fw4-restore.nft" "$backup/restore-saved.nft"
awk '{print $0 " # handle 1"}' "$backup/candidate.nft" > "$backup/candidate-handles.nft"
inspect_rules "$backup/candidate-handles.nft" fw4 || fail 'Rendered owned firewall rules differ from exact mappings.'
if [ "$action" = apply ]; then
  [ "$(wc -l < "$backup/fw4-delete.nft")" -eq "$expected_count" ] || fail 'Rendered firewall omitted camera rules.'
else
  if grep -Fq "comment \"!fw4: $prefix" "$backup/candidate.nft"; then fail 'Rendered firewall retained camera rules.'; fi
fi
cp "$backup/delete-saved.nft" "$backup/fw4-delete.nft"
cp "$backup/restore-saved.nft" "$backup/fw4-restore.nft"
: > "$backup/rollback.nft"
[ "$action" != apply ] || printf 'delete table inet %s\n' "$table" >> "$backup/rollback.nft"
[ "$had_table" = 0 ] || cat "$backup/table-before.nft" >> "$backup/rollback.nft"
cat "$backup/fw4-restore.nft" >> "$backup/rollback.nft"
[ "$(sha256sum /etc/config/firewall | awk '{print $1}')" = "$before_hash" ] || fail 'Firewall changed concurrently before commit.'
if [ "$mode" = lan ]; then
  [ "$(sha256sum /etc/config/network | awk '{print $1}')" = "$network_before_hash" ] || fail 'Network configuration changed concurrently before commit.'
fi
# Defer parent termination across persistent commit and the nft transaction.
# Otherwise a signal between success and bookkeeping can escape restoration or
# restore already-present rules twice.
pending_signal=0
trap 'pending_signal=130' HUP INT
trap 'pending_signal=143' TERM
if [ "$mode" = lan ] && [ "$action" = remove ]; then
  # Remove local delivery before the guards. No other address is touched.
  for suffix in $suffixes; do
    address=10.20.0.$suffix
    if ip -4 -o addr show | grep -Fq "inet $address/32"; then
      ip addr del "$address/32" dev eth0.2
      removed_addresses="$removed_addresses $address"
    fi
  done
fi
# Removal commits alias deletion before dropping persisted guards. Installation
# does the reverse, so even a power loss between the two commits fails closed.
if [ "$mode" = lan ] && [ "$action" = remove ]; then
  uci commit network
  network_committed=1
  network_hash=$(sha256sum /etc/config/network | awk '{print $1}')
fi
uci commit firewall
committed=1
committed_hash=$(sha256sum /etc/config/firewall | awk '{print $1}')
if [ "$mode" = lan ] && [ "$action" != remove ]; then
  uci commit network
  network_committed=1
  network_hash=$(sha256sum /etc/config/network | awk '{print $1}')
fi
if nft -f "$backup/change.nft"; then applied=1
else fail 'Atomic camera ruleset transaction failed; live nft state was not changed.'; fi
if [ "$action" = apply ]; then
  nft list table inet "$table" > "$backup/table-after.nft"
  inspect_rules "$backup/table-after.nft" table || fail 'Live camera table verification failed.'
  if [ "$mode" = lan ]; then
    for suffix in $suffixes; do
      address=10.20.0.$suffix
      if ! ip -4 -o addr show | grep -Fq "inet $address/32"; then
        ip addr add "$address/32" dev eth0.2
        added_addresses="$added_addresses $address"
      fi
    done
    check_aliases
    [ "$alias_count" = 6 ] || fail 'Alias persistence verification failed.'
    for suffix in $suffixes; do ip -4 -o addr show | grep -Fq "inet 10.20.0.$suffix/32" || fail 'Live alias verification failed.'; done
  fi
else
  if nft list table inet "$table" >/dev/null 2>&1; then fail 'Live camera table remains after removal.'; fi
fi
trap 'exit 130' HUP INT
trap 'exit 143' TERM
[ "$pending_signal" = 0 ] || exit "$pending_signal"
committed=0
network_committed=0
applied=0
added_addresses=
removed_addresses=
printf '%s camera %s completed; no network/service reload. Firewall UCI text growth: %s bytes. Backup: %s\n' "$mode" "$action" "$(( $(wc -c < /etc/config/firewall) - firewall_bytes ))" "$backup"
printf '%s\n' 'Existing conntrack sessions are retained. Copy private backups off Mango before reboot.'
exit 0
