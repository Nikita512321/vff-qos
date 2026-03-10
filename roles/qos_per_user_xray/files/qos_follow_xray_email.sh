#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin

ENV_FILE="${ENV_FILE:-/etc/vff-qos/qos.env}"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE"

CONTAINER="${CONTAINER:-remnanode}"
XRAY_LOG="${XRAY_LOG:-/var/log/supervisor/xray.out.log}"
LOG_SOURCE="${LOG_SOURCE:-docker}" # docker | host

WAN_DEV="${WAN_DEV:-auto}"
IFB_DEV="${IFB_DEV:-ifb0}"

UPLOAD_DEFAULT="${UPLOAD_DEFAULT:-1000mbit}"
DOWNLOAD_DEFAULT="${DOWNLOAD_DEFAULT:-1000mbit}"
VPN_PORT="${VPN_PORT:-443}"

DRY_RUN="${DRY_RUN:-0}"

# Cache knobs:
# - TC_ENSURE_TTL_SEC: skip repeated tc ensure for same mark within TTL (effective for noisy clients)
# - CT_CACHE_TCP_TTL_SEC / CT_CACHE_UDP_TTL_SEC: skip duplicate conntrack updates for same flow key
TC_ENSURE_TTL_SEC="${TC_ENSURE_TTL_SEC:-60}"
CT_CACHE_TCP_TTL_SEC="${CT_CACHE_TCP_TTL_SEC:-0}"
CT_CACHE_UDP_TTL_SEC="${CT_CACHE_UDP_TTL_SEC:-2}"

log(){ echo "[$(date '+%F %T')] $*"; }

detect_wan_if() {
  ip -4 route show default 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

detect_server_ip4() {
  ip -4 route get 1.1.1.1 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

detect_server_ip6() {
  ip -6 route get 2606:4700:4700::1111 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

run(){
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "+ $*"
  else
    eval "$@"
  fi
}

now_epoch() {
  date +%s
}

declare -A tc_ensure_cache_ts
declare -A ct_cache_ts

should_skip_by_ttl() {
  local key="$1" ttl="$2" now="$3" cache_name="$4"
  local last=0

  [[ "$ttl" =~ ^[0-9]+$ ]] || ttl=0
  (( ttl > 0 )) || return 1

  if [[ "$cache_name" == "tc" ]]; then
    last="${tc_ensure_cache_ts[$key]:-0}"
  else
    last="${ct_cache_ts[$key]:-0}"
  fi

  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  (( now - last < ttl )) || return 1
  return 0
}

touch_cache() {
  local key="$1" now="$2" cache_name="$3"
  if [[ "$cache_name" == "tc" ]]; then
    tc_ensure_cache_ts["$key"]="$now"
  else
    ct_cache_ts["$key"]="$now"
  fi
}

# Resolve WAN_DEV=auto
if [[ -z "${WAN_DEV:-}" || "${WAN_DEV}" == "auto" ]]; then
  WAN_DEV="$(detect_wan_if || true)"
fi
if [[ -z "${WAN_DEV:-}" ]]; then
  log "ERROR: cannot determine WAN_DEV (set WAN_DEV=... in $ENV_FILE)"
  exit 1
fi

# Determine server IPs (dst of incoming)
SERVER_IP="${SERVER_IP:-$(detect_server_ip4 || true)}"
SERVER_IP6="${SERVER_IP6:-$(detect_server_ip6 || true)}"
if [[ -z "${SERVER_IP:-}" && -z "${SERVER_IP6:-}" ]]; then
  log "ERROR: cannot determine SERVER_IP/SERVER_IP6 (set one manually in $ENV_FILE)"
  exit 1
fi

# Safety: do not proceed until bootstrap has created base qdisc 1:/2:
ensure_bootstrap_ready() {
  tc qdisc show dev "$WAN_DEV" 2>/dev/null | grep -q 'htb 1:' || return 1
  tc qdisc show dev "$IFB_DEV" 2>/dev/null | grep -q 'htb 2:' || return 1
  return 0
}

email_to_mark() {
  local email="$1"
  local c
  c="$(printf '%s' "$email" | cksum | awk '{print $1}')"
  local m=$(( c & 0xffff ))
  # avoid reserved values / special
  if [[ "$m" -eq 0 || "$m" -eq 65534 || "$m" -eq 65535 ]]; then
    m=$(( (m + 1) & 0xffff ))
    [[ "$m" -eq 0 ]] && m=1
  fi
  echo "$m"
}

get_rates_for_email() {
  local _email="$1"
  # пока дефолты; дальше можно подключить таблицу тарифов/override
  echo "$UPLOAD_DEFAULT" "$DOWNLOAD_DEFAULT"
}

class_exists() {
  local dev="$1" classid="$2"
  tc class show dev "$dev" classid "$classid" 2>/dev/null | grep -q .
}

ensure_class_htb() {
  local dev="$1" parent="$2" classid="$3" rate="$4"
  if class_exists "$dev" "$classid"; then
    run "tc class change dev $dev parent $parent classid $classid htb rate $rate ceil $rate"
  else
    run "tc class add dev $dev parent $parent classid $classid htb rate $rate ceil $rate"
  fi
}

# purge any existing fw-filters for this handle (they can accumulate if earlier versions used varying pref)
purge_fw_filters_by_handle() {
  local dev="$1" parent="$2" handle="$3" l3_proto="${4:-}"
  # tc output contains lines like: "filter protocol ip pref 41980 fw ... handle 0x27cd ..."
  tc filter show dev "$dev" parent "$parent" 2>/dev/null \
    | awk -v h="$handle" -v p="$l3_proto" '
        $1=="filter" && $2=="protocol" {
          proto=$3; pref=""
          for(i=1;i<=NF;i++) if($i=="pref"){pref=$(i+1)}
        }
        $0 ~ ("handle " h) {
          if (proto != "" && pref != "" && (p == "" || proto == p)) print proto "\t" pref
        }
      ' \
    | while IFS=$'\t' read -r proto pref; do
        [[ -n "$proto" && -n "$pref" ]] || continue
        tc filter del dev "$dev" parent "$parent" protocol "$proto" pref "$pref" 2>/dev/null || true
      done
}

ensure_fw_filter() {
  local dev="$1" parent="$2" handle="$3" flowid="$4" pref="$5" l3_proto="$6"
  purge_fw_filters_by_handle "$dev" "$parent" "$handle" "$l3_proto"
  run "tc filter add dev $dev parent $parent protocol $l3_proto pref $pref handle $handle fw flowid $flowid"
}

ensure_tc_for_mark() {
  local mark_dec="$1" ul_rate="$2" dl_rate="$3"

  local hex handle ul_class dl_class pref
  hex="$(printf '%x' "$mark_dec")"
  handle="0x${hex}"
  ul_class="2:${hex}"
  dl_class="1:${hex}"

  # tc pref must be <= 65535; mark_dec is already 1..65533
  pref="$mark_dec"

  log "  [UL] ensure class $ul_class on $IFB_DEV rate=$ul_rate"
  ensure_class_htb "$IFB_DEV" "2:1" "$ul_class" "$ul_rate"
  log "  [UL] ensure fw filter handle=$handle -> $ul_class on $IFB_DEV (all)"
  ensure_fw_filter "$IFB_DEV" "2:" "$handle" "$ul_class" "$pref" "all"

  log "  [DL] ensure class $dl_class on $WAN_DEV rate=$dl_rate"
  ensure_class_htb "$WAN_DEV" "1:1" "$dl_class" "$dl_rate"
  log "  [DL] ensure fw filter handle=$handle -> $dl_class on $WAN_DEV (all)"
  ensure_fw_filter "$WAN_DEV" "1:" "$handle" "$dl_class" "$pref" "all"
}

update_conntrack_mark() {
  local proto="$1" ip="$2" port="$3" mark_dec="$4"
  local family server_ip
  if [[ "$ip" == *:* ]]; then
    family="ipv6"
    server_ip="${SERVER_IP6:-}"
  else
    family="ipv4"
    server_ip="${SERVER_IP:-}"
  fi

  if [[ -z "$server_ip" ]]; then
    log "  [CT] skip: missing server IP for family=$family (set SERVER_IP/SERVER_IP6)"
    return 0
  fi

  local cmd
  cmd="conntrack -U -f ${family} -p ${proto} --orig-src ${ip} --orig-dst ${server_ip} --orig-port-src ${port} --orig-port-dst ${VPN_PORT} --mark ${mark_dec}"

  log "  [CT] $cmd"
  run "$cmd" || true

  if [[ "$DRY_RUN" == "0" ]]; then
    conntrack -L -f "$family" -p "$proto" 2>/dev/null \
      | grep -F "src=${ip} " \
      | grep -F "sport=${port} " \
      | grep -F "dport=${VPN_PORT} " \
      | head -n 1 \
      | sed 's/^/[CT now] /' || true
  fi
}

ct_ttl_for_proto() {
  local proto="$1"
  if [[ "$proto" == "udp" ]]; then
    echo "$CT_CACHE_UDP_TTL_SEC"
  else
    echo "$CT_CACHE_TCP_TTL_SEC"
  fi
}

log "start: container=$CONTAINER log=$XRAY_LOG WAN_DEV=$WAN_DEV IFB_DEV=$IFB_DEV SERVER_IP=$SERVER_IP SERVER_IP6=${SERVER_IP6:-n/a} VPN_PORT=$VPN_PORT tc_ttl=${TC_ENSURE_TTL_SEC}s ct_tcp_ttl=${CT_CACHE_TCP_TTL_SEC}s ct_udp_ttl=${CT_CACHE_UDP_TTL_SEC}s"

# wait until bootstrap is ready (important on boot / restarts)
until ensure_bootstrap_ready; do
  log "bootstrap not ready yet (missing htb 1:/2:). waiting..."
  sleep 2
done

stream_xray_log() {
  case "$LOG_SOURCE" in
    docker)
      docker exec -i "$CONTAINER" sh -lc "tail -n0 -F '$XRAY_LOG'"
      ;;
    host)
      tail -n0 -F "$XRAY_LOG"
      ;;
    *)
      log "ERROR: unsupported LOG_SOURCE='$LOG_SOURCE' (expected: docker|host)"
      return 1
      ;;
  esac
}

stream_xray_log \
| while IFS= read -r line; do
    ip=""
    port=""
    proto=""
    email=""

    [[ "$line" == *" accepted "* && "$line" == *" email:"* && "$line" == *" from "* ]] || continue

    if [[ "$line" =~ from[[:space:]]\[([0-9A-Fa-f:]+)\]:([0-9]+)[[:space:]].*accepted[[:space:]](tcp|udp):.*email:[[:space:]]([^[:space:]]+) ]]; then
      ip="${BASH_REMATCH[1]}"
      port="${BASH_REMATCH[2]}"
      proto="${BASH_REMATCH[3]}"
      email="${BASH_REMATCH[4]}"
    elif [[ "$line" =~ from[[:space:]]([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)[[:space:]].*accepted[[:space:]](tcp|udp):.*email:[[:space:]]([^[:space:]]+) ]]; then
      ip="${BASH_REMATCH[1]}"
      port="${BASH_REMATCH[2]}"
      proto="${BASH_REMATCH[3]}"
      email="${BASH_REMATCH[4]}"
    elif [[ "$line" =~ from[[:space:]]([0-9A-Fa-f:]+):([0-9]+)[[:space:]].*accepted[[:space:]](tcp|udp):.*email:[[:space:]]([^[:space:]]+) ]]; then
      ip="${BASH_REMATCH[1]}"
      port="${BASH_REMATCH[2]}"
      proto="${BASH_REMATCH[3]}"
      email="${BASH_REMATCH[4]}"
    fi

    if [[ -n "$ip" && -n "$port" && -n "$proto" && -n "$email" ]]; then
      read -r ul dl < <(get_rates_for_email "$email")
      mark="$(email_to_mark "$email")"
      now="$(now_epoch)"

      if [[ "$ip" == *:* ]]; then
        log "event: proto=$proto email=$email ip=[$ip]:$port mark=$(printf '0x%x' "$mark") ul=$ul dl=$dl"
      else
        log "event: proto=$proto email=$email ip=$ip:$port mark=$(printf '0x%x' "$mark") ul=$ul dl=$dl"
      fi

      tc_key="$mark"
      if should_skip_by_ttl "$tc_key" "$TC_ENSURE_TTL_SEC" "$now" "tc"; then
        log "  [TC] skip ensure for mark=$(printf '0x%x' "$mark") (ttl=${TC_ENSURE_TTL_SEC}s)"
      else
        ensure_tc_for_mark "$mark" "$ul" "$dl"
        touch_cache "$tc_key" "$now" "tc"
      fi

      ct_ttl="$(ct_ttl_for_proto "$proto")"
      # UDP often opens many short-lived ports; cache by src IP + mark to reduce update bursts.
      # TCP keeps per-flow key (with src port) to preserve marking precision.
      if [[ "$proto" == "udp" ]]; then
        ct_key="${proto}|${ip}|${mark}"
      else
        ct_key="${proto}|${ip}|${port}|${mark}"
      fi
      if should_skip_by_ttl "$ct_key" "$ct_ttl" "$now" "ct"; then
        log "  [CT] skip conntrack update for flow=$proto/$ip:$port mark=$(printf '0x%x' "$mark") (ttl=${ct_ttl}s)"
      else
        update_conntrack_mark "$proto" "$ip" "$port" "$mark"
        touch_cache "$ct_key" "$now" "ct"
      fi
    fi
  done
