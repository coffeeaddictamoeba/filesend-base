#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"

die()  { echo "[ERROR] $*" >&2; exit 1; }
warn() { echo "[WARN]  $*" >&2; }
log()  { echo "[INFO]  $*"; }

trap 'ec=$?; (( ec == 0 )) || warn "Script failed with exit code $ec."' EXIT

usage() {
  cat <<EOF
Usage:
  $SCRIPT_NAME <incoming_dir> [config.json] [--force[=all|server|devices]]
  $SCRIPT_NAME <incoming_dir> [config.json] --devices <id1,id2,...> [--force[=all|server|devices]]
  $SCRIPT_NAME <incoming_dir> [config.json] --add-device <id> [--force[=all|server|devices]]
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

for cmd in docker python3 grep sed find cp mkdir chmod id rm dirname basename pwd sort tr; do
  require_cmd "$cmd"
done

INCOMING_DIR=""
CONFIG_FILE="setup.json"
FORCE_MODE=""
DEVICE_SELECTION_RAW=""
ADD_DEVICE_ID=""

REPO_ROOT=""
SERVER_DOCKERFILE=""
SERVER_IMAGE=""
SERVER_CONTAINER_NAME=""
SERVER_WORKSPACE_DIR=""

APP_DOCKERFILE=""
APP_IMAGE=""
APP_ENCRYPT_RAW=""

CONN_MODE_RAW=""
CONN_URL_RAW=""

CONN_MODE=""
ENCRYPT_MODE=""
SERVER_HOST=""
SERVER_PORT=""
CONN_URL=""

SERVER_WORKSPACE_ABS=""

GENERATE_CONFIGS_SCRIPT=""
GENERATE_SECURITY_SCRIPT=""
ROOT_FILESEND_CONFIG=""
SERVER_CONFIG_PATH=""
SERVER_CONFIG_MIRROR_PATH=""

CRYPTO_ROOT=""
ASYMM_ROOT=""
SYMM_ROOT=""
CA_DIR=""
CLIENT_SERVER_CRYPTO_DIR=""
DEVICES_ROOT=""

ACTIVE_DATE_TAG=""
ACTIVE_CA_SRC=""
ACTIVE_PUB_SRC=""
ACTIVE_PR_SRC=""
ACTIVE_SYM_SRC=""
ACTIVE_SERVER_CERT_SRC=""
ACTIVE_SERVER_KEY_SRC=""

ACTIVE_CA_BASENAME=""
ACTIVE_PUB_BASENAME=""
ACTIVE_PR_BASENAME=""
ACTIVE_SYM_BASENAME=""
ACTIVE_SERVER_CERT_BASENAME=""
ACTIVE_SERVER_KEY_BASENAME=""

DEVICES=()
SELECTED_DEVICES=()

parse_args() {
  [[ $# -ge 1 ]] || { usage; exit 1; }

  INCOMING_DIR="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      *.json) CONFIG_FILE="$1" ;;
      --force) FORCE_MODE="all" ;;
      --force=*) FORCE_MODE="${1#--force=}" ;;
      --devices)
        shift
        [[ $# -gt 0 ]] || die "--devices requires a value"
        DEVICE_SELECTION_RAW="$1"
        ;;
      --add-device)
        shift
        [[ $# -gt 0 ]] || die "--add-device requires a value"
        ADD_DEVICE_ID="$1"
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
    shift
  done

  [[ -n "$INCOMING_DIR" ]] || die "Incoming directory must not be empty."
  [[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"

  case "$FORCE_MODE" in
    ""|all|server|devices) ;;
    *) die "Invalid --force value: $FORCE_MODE" ;;
  esac

  [[ -z "$DEVICE_SELECTION_RAW" || -z "$ADD_DEVICE_ID" ]] || die "Use either --devices or --add-device, not both."
}

should_force_all()     { [[ "$FORCE_MODE" == "all" ]]; }
should_force_server()  { [[ "$FORCE_MODE" == "all" || "$FORCE_MODE" == "server" ]]; }
should_force_devices() { [[ "$FORCE_MODE" == "all" || "$FORCE_MODE" == "devices" ]]; }

json_get() {
  local path="$1"
  python3 - "$CONFIG_FILE" "$path" <<'PY'
import json, sys
cfg_path, dotted = sys.argv[1], sys.argv[2]
with open(cfg_path, "r", encoding="utf-8") as f:
    data = json.load(f)

cur = data
for part in dotted.split("."):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        print("")
        raise SystemExit(0)

print(cur if isinstance(cur, str) else "")
PY
}

json_list_devices() {
  python3 - "$CONFIG_FILE" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

for dev in data.get("devices", []):
    dev_id = dev.get("id")
    if isinstance(dev_id, str) and dev_id:
        print(dev_id)
PY
}

normalize_connection_mode() {
  local mode
  mode="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    ""|ws|wss) printf '%s\n' "ws" ;;
    http|https) printf '%s\n' "http" ;;
    *) die "Unsupported server_connection.mode: $1" ;;
  esac
}

normalize_encrypt_mode() {
  local mode
  mode="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    ""|asymm|asymmetric) printf '%s\n' "asymm" ;;
    symm|symmetric)      printf '%s\n' "symm" ;;
    no|none|off)         printf '%s\n' "no" ;;
    *) die "Unsupported app.encrypt: $1" ;;
  esac
}

extract_host_from_url() {
  local raw="${1:-}"
  python3 - "$raw" <<'PY'
import sys
from urllib.parse import urlsplit

raw = (sys.argv[1] or "").strip()
if not raw:
    print("0.0.0.0")
    raise SystemExit(0)

candidate = raw if "://" in raw else f"dummy://{raw}"
u = urlsplit(candidate)
if u.hostname:
    print(u.hostname)
else:
    raise SystemExit(f"Could not extract host from server_connection.url: {raw}")
PY
}

extract_port_from_url() {
  local raw="${1:-}"
  local mode="${2:-ws}"

  python3 - "$raw" "$mode" <<'PY'
import sys
from urllib.parse import urlsplit

raw = (sys.argv[1] or "").strip()
mode = (sys.argv[2] or "ws").strip().lower()
default_port = 8444 if mode == "ws" else 8443

if not raw:
    print(default_port)
    raise SystemExit(0)

candidate = raw if "://" in raw else f"dummy://{raw}"
u = urlsplit(candidate)
print(u.port if u.port is not None else default_port)
PY
}

resolve_filesend_url() {
  local mode="$1" raw_url="$2"
  local host port

  host="$(extract_host_from_url "$raw_url")"
  port="$(extract_port_from_url "$raw_url" "$mode")"

  if [[ "$host" == *:* && "$host" != \[*\] ]]; then
    host="[$host]"
  fi

  case "$mode" in
    ws)   printf '%s\n' "wss://${host}:${port}" ;;
    http) printf '%s\n' "https://${host}:${port}/upload" ;;
    *) die "Cannot resolve filesend URL for mode: $mode" ;;
  esac
}

set_config_value() {
  local file="$1" key="$2" value="$3"
  [[ -f "$file" ]] || die "Config file not found: $file"

  if grep -Eq "^[[:space:]]*${key}[[:space:]]*[:=]" "$file"; then
    sed -i -E "s|^([[:space:]]*${key}[[:space:]]*[:=][[:space:]]*).*$|\1${value}|" "$file"
  else
    printf '\n%s = %s\n' "$key" "$value" >> "$file"
  fi
}

remove_config_key() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || die "Config file not found: $file"
  sed -i -E "/^[[:space:]]*${key}[[:space:]]*[:=].*$/d" "$file"
}

rename_ini_section() {
  local file="$1" old="$2" new="$3"
  [[ -f "$file" ]] || die "Config file not found: $file"
  sed -i -E "s|^[[:space:]]*\[${old}\][[:space:]]*$|[${new}]|" "$file"
}

ensure_ini_section_name() {
  local file="$1" target="$2"
  [[ -f "$file" ]] || die "Config file not found: $file"

  if grep -Eq "^[[:space:]]*\[inactive\][[:space:]]*$" "$file"; then
    sed -i -E "s|^[[:space:]]*\[inactive\][[:space:]]*$|[${target}]|" "$file"
  elif grep -Eq "^[[:space:]]*\[removed\][[:space:]]*$" "$file"; then
    sed -i -E "s|^[[:space:]]*\[removed\][[:space:]]*$|[${target}]|" "$file"
  fi
}

docker_build() {
  local image="$1" dockerfile="$2" uid_arg="$3" gid_arg="$4"
  log "Building image: $image"
  (
    cd "$REPO_ROOT"
    docker build \
      -f "$dockerfile" \
      --build-arg "$uid_arg=$(id -u)" \
      --build-arg "$gid_arg=$(id -g)" \
      -t "$image" \
      .
  )
}

image_exists() {
  docker image inspect "$1" >/dev/null 2>&1
}

generate_base_configs() {
  [[ -f "$GENERATE_CONFIGS_SCRIPT" ]] || die "generate-configs.sh not found: $GENERATE_CONFIGS_SCRIPT"

  log "Generating base configs"
  (
    cd "$REPO_ROOT"
    chmod +x "$GENERATE_CONFIGS_SCRIPT"
    "$GENERATE_CONFIGS_SCRIPT" "$REPO_ROOT" --container "$SERVER_CONTAINER_NAME"
  )

  [[ -f "$ROOT_FILESEND_CONFIG" ]] || die "Generated root filesend_config not found: $ROOT_FILESEND_CONFIG"
  [[ -f "$SERVER_CONFIG_PATH"  ]] || die "Generated server/server_config not found: $SERVER_CONFIG_PATH"
}

ensure_base_configs() {
  if should_force_server || [[ ! -f "$ROOT_FILESEND_CONFIG" || ! -f "$SERVER_CONFIG_PATH" ]]; then
    generate_base_configs
  else
    log "Reusing existing generated configs"
  fi
}

ensure_server_images() {
  if should_force_server || ! image_exists "$SERVER_IMAGE"; then
    docker_build "$SERVER_IMAGE" "$SERVER_DOCKERFILE" USER_UID USER_GID
  else
    log "Reusing existing server image: $SERVER_IMAGE"
  fi

  if should_force_all || ! image_exists "$APP_IMAGE"; then
    docker_build "$APP_IMAGE" "$APP_DOCKERFILE" USER_ID GROUP_ID
  else
    log "Reusing existing app image: $APP_IMAGE"
  fi
}

ensure_security_material() {
  [[ -f "$GENERATE_SECURITY_SCRIPT" ]] || die "generate-security.sh not found: $GENERATE_SECURITY_SCRIPT"
  chmod +x "$GENERATE_SECURITY_SCRIPT"

  local args=(. --image "$SERVER_IMAGE")
  if should_force_server; then
    args+=(--force=all)
  fi

  log "Generating or repairing security material"
  (
    cd "$SERVER_WORKSPACE_ABS"
    "$GENERATE_SECURITY_SCRIPT" "${args[@]}"
  )
}

extract_date_from_filename() {
  local name="$1"
  if [[ "$name" =~ ([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

select_complete_dated_bundle() {
  local server_keys="$SERVER_WORKSPACE_ABS/keys"
  local server_certs="$SERVER_WORKSPACE_ABS/certs"

  mkdir -p "$server_keys" "$server_certs"

  local dates=() path="" date=""
  while IFS= read -r path; do
    date="$(extract_date_from_filename "$(basename "$path")" || true)"
    [[ -n "$date" ]] && dates+=("$date")
  done < <(find "$server_keys" "$server_certs" -maxdepth 1 -type f | sort)

  [[ "${#dates[@]}" -gt 0 ]] || die "No dated security material found in $server_keys or $server_certs"

  local selected="" d
  while IFS= read -r d; do
    local ca="$server_certs/ca_cert-${d}.pem"
    local crt="$server_certs/server-${d}.crt"
    local key="$server_keys/server-${d}.key"

    case "$ENCRYPT_MODE" in
      asymm)
        [[ -f "$ca" && -f "$crt" && -f "$key" \
           && -f "$server_keys/pub_key-${d}.bin" \
           && -f "$server_keys/pr_key-${d}.bin" ]] && selected="$d"
        ;;
      symm)
        [[ -f "$ca" && -f "$crt" && -f "$key" \
           && -f "$server_keys/sym_key-${d}.bin" ]] && selected="$d"
        ;;
      no)
        [[ -f "$ca" && -f "$crt" && -f "$key" ]] && selected="$d"
        ;;
    esac
  done < <(printf '%s\n' "${dates[@]}" | sort -u)

  [[ -n "$selected" ]] || die "No complete dated security bundle found for encryption mode '$ENCRYPT_MODE'"

  ACTIVE_DATE_TAG="$selected"
  ACTIVE_CA_SRC="$server_certs/ca_cert-${selected}.pem"
  ACTIVE_SERVER_CERT_SRC="$server_certs/server-${selected}.crt"
  ACTIVE_SERVER_KEY_SRC="$server_keys/server-${selected}.key"

  ACTIVE_PUB_SRC=""
  ACTIVE_PR_SRC=""
  ACTIVE_SYM_SRC=""

  case "$ENCRYPT_MODE" in
    asymm)
      ACTIVE_PUB_SRC="$server_keys/pub_key-${selected}.bin"
      ACTIVE_PR_SRC="$server_keys/pr_key-${selected}.bin"
      ;;
    symm)
      ACTIVE_SYM_SRC="$server_keys/sym_key-${selected}.bin"
      ;;
  esac

  ACTIVE_CA_BASENAME="$(basename "$ACTIVE_CA_SRC")"
  ACTIVE_SERVER_CERT_BASENAME="$(basename "$ACTIVE_SERVER_CERT_SRC")"
  ACTIVE_SERVER_KEY_BASENAME="$(basename "$ACTIVE_SERVER_KEY_SRC")"
  ACTIVE_PUB_BASENAME="${ACTIVE_PUB_SRC:+$(basename "$ACTIVE_PUB_SRC")}"
  ACTIVE_PR_BASENAME="${ACTIVE_PR_SRC:+$(basename "$ACTIVE_PR_SRC")}"
  ACTIVE_SYM_BASENAME="${ACTIVE_SYM_SRC:+$(basename "$ACTIVE_SYM_SRC")}"

  log "Selected dated security bundle: $ACTIVE_DATE_TAG"
}

copy_active_file_if_present() {
  local src="$1" dst_dir="$2"
  [[ -n "$src" ]] || return 0
  [[ -f "$src" ]] || die "Missing active source file: $src"
  mkdir -p "$dst_dir"
  cp -f "$src" "$dst_dir/"
}

mirror_client_security_material() {
  mkdir -p "$CA_DIR" "$CLIENT_SERVER_CRYPTO_DIR" "$SYMM_ROOT"

  copy_active_file_if_present "$ACTIVE_CA_SRC" "$CA_DIR"

  case "$ENCRYPT_MODE" in
    asymm)
      copy_active_file_if_present "$ACTIVE_PUB_SRC" "$CLIENT_SERVER_CRYPTO_DIR"
      copy_active_file_if_present "$ACTIVE_PR_SRC" "$CLIENT_SERVER_CRYPTO_DIR"
      ;;
    symm)
      copy_active_file_if_present "$ACTIVE_SYM_SRC" "$SYMM_ROOT"
      ;;
  esac

  log "Mirrored client-facing security material into repo crypto directories"
}

apply_encrypt_mode_to_config() {
  local cfg="$1" scope="$2" device_dir="${3:-}"

  case "$ENCRYPT_MODE" in
    asymm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "asymmetric"

      if [[ "$scope" == "root" ]]; then
        set_config_value "$cfg" "pub_key_path" "crypto/asymm/server/${ACTIVE_PUB_BASENAME}"
        set_config_value "$cfg" "pr_key_path"  "crypto/asymm/server/${ACTIVE_PR_BASENAME}"
      elif [[ "$scope" == "device" ]]; then
        [[ -n "$device_dir" ]] || die "device_dir required for device crypto config"
        copy_active_file_if_present "$ACTIVE_PUB_SRC" "$device_dir"
        set_config_value "$cfg" "pub_key_path" "$ACTIVE_PUB_BASENAME"
        remove_config_key "$cfg" "pr_key_path"
      fi

      remove_config_key "$cfg" "sym_key_path"
      ;;

    symm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "symmetric"

      if [[ "$scope" == "root" ]]; then
        set_config_value "$cfg" "sym_key_path" "crypto/symm/${ACTIVE_SYM_BASENAME}"
      elif [[ "$scope" == "device" ]]; then
        [[ -n "$device_dir" ]] || die "device_dir required for device crypto config"
        copy_active_file_if_present "$ACTIVE_SYM_SRC" "$device_dir"
        set_config_value "$cfg" "sym_key_path" "$ACTIVE_SYM_BASENAME"
      fi

      remove_config_key "$cfg" "pub_key_path"
      remove_config_key "$cfg" "pr_key_path"
      ;;

    no)
      grep -Eq '^[[:space:]]*\[crypto\][[:space:]]*$' "$cfg"  && rename_ini_section "$cfg" "crypto" "inactive" || true
      grep -Eq '^[[:space:]]*\[removed\][[:space:]]*$' "$cfg" && rename_ini_section "$cfg" "removed" "inactive" || true
      remove_config_key "$cfg" "pub_key_path"
      remove_config_key "$cfg" "pr_key_path"
      remove_config_key "$cfg" "sym_key_path"
      ;;
  esac
}

update_root_filesend_config() {
  [[ -f "$ROOT_FILESEND_CONFIG" ]] || die "Missing root filesend_config: $ROOT_FILESEND_CONFIG"

  set_config_value "$ROOT_FILESEND_CONFIG" "cert_path" "crypto/asymm/CA/${ACTIVE_CA_BASENAME}"
  apply_encrypt_mode_to_config "$ROOT_FILESEND_CONFIG" "root"
  set_config_value "$ROOT_FILESEND_CONFIG" "use_ws" "$([[ "$CONN_MODE" == "ws" ]] && echo true || echo false)"
  set_config_value "$ROOT_FILESEND_CONFIG" "url" "$CONN_URL"
}

update_generated_server_config() {
  [[ -f "$SERVER_CONFIG_PATH" ]] || die "Missing generated server config: $SERVER_CONFIG_PATH"

  set_config_value "$SERVER_CONFIG_PATH" "host" "$SERVER_HOST"
  set_config_value "$SERVER_CONFIG_PATH" "port" "$SERVER_PORT"
  set_config_value "$SERVER_CONFIG_PATH" "cert_path" "certs/${ACTIVE_SERVER_CERT_BASENAME}"
  set_config_value "$SERVER_CONFIG_PATH" "key_path"  "keys/${ACTIVE_SERVER_KEY_BASENAME}"

  mkdir -p "$(dirname "$SERVER_CONFIG_MIRROR_PATH")"
  cp -f "$SERVER_CONFIG_PATH" "$SERVER_CONFIG_MIRROR_PATH"
  log "Updated server config mirror: $SERVER_CONFIG_MIRROR_PATH"
}

normalize_incoming_subpath() {
  local raw="$1"
  local clean="${raw#./}"
  clean="${clean#/}"
  clean="${clean%/}"
  [[ -n "$clean" ]] || die "Incoming directory must not be empty."
  [[ "$clean" != *".."* ]] || die "Incoming directory must not contain '..'"
  printf '%s\n' "$clean"
}

prepare_device_dir() {
  local device_id="$1"
  local incoming_subpath="$2"
  local device_dir="$DEVICES_ROOT/$device_id"
  local device_cfg="$device_dir/filesend_config"

  mkdir -p "$device_dir"
  cp -f "$ROOT_FILESEND_CONFIG" "$device_cfg"

  copy_active_file_if_present "$ACTIVE_CA_SRC" "$device_dir"
  set_config_value "$device_cfg" "cert_path" "$ACTIVE_CA_BASENAME"

  apply_encrypt_mode_to_config "$device_cfg" "device" "$device_dir"
  set_config_value "$device_cfg" "use_ws" "$([[ "$CONN_MODE" == "ws" ]] && echo true || echo false)"
  set_config_value "$device_cfg" "url" "$CONN_URL"
  set_config_value "$device_cfg" "device_id" "$device_id"

  mkdir -p "$device_dir/$incoming_subpath"

  log "Prepared device directory: $device_dir"
  log "Prepared incoming directory: $device_dir/$incoming_subpath"
}

resolve_selected_devices() {
  if [[ -n "$ADD_DEVICE_ID" ]]; then
    SELECTED_DEVICES=("$ADD_DEVICE_ID")
  elif [[ -n "$DEVICE_SELECTION_RAW" ]]; then
    IFS=',' read -r -a SELECTED_DEVICES <<< "$DEVICE_SELECTION_RAW"
    [[ ${#SELECTED_DEVICES[@]} -gt 0 ]] || die "No device ids parsed from --devices."
  else
    SELECTED_DEVICES=("${DEVICES[@]}")
  fi
}

prepare_devices() {
  local incoming_subpath="$1"
  local device_id

  if should_force_devices && [[ -z "$ADD_DEVICE_ID" ]]; then
    log "Forcing rebuild of selected device directories"
    for device_id in "${SELECTED_DEVICES[@]}"; do
      rm -rf -- "$DEVICES_ROOT/$device_id"
    done
  fi

  for device_id in "${SELECTED_DEVICES[@]}"; do
    [[ -n "$device_id" ]] || continue
    prepare_device_dir "$device_id" "$incoming_subpath"
  done
}

load_config() {
  REPO_ROOT="$(json_get "repo_root")"
  REPO_ROOT="${REPO_ROOT:-.}"

  SERVER_DOCKERFILE="$(json_get "server.dockerfile")"
  SERVER_IMAGE="$(json_get "server.image")"
  SERVER_CONTAINER_NAME="$(json_get "server.container_name")"
  SERVER_WORKSPACE_DIR="$(json_get "server.workspace_dir")"

  APP_DOCKERFILE="$(json_get "app.dockerfile")"
  APP_IMAGE="$(json_get "app.image")"
  APP_ENCRYPT_RAW="$(json_get "app.encrypt")"

  CONN_MODE_RAW="$(json_get "server_connection.mode")"
  CONN_URL_RAW="$(json_get "server_connection.url")"

  mapfile -t DEVICES < <(json_list_devices)

  SERVER_DOCKERFILE="${SERVER_DOCKERFILE:-Dockerfile.server}"
  SERVER_IMAGE="${SERVER_IMAGE:-filesend-server-dev}"
  SERVER_CONTAINER_NAME="${SERVER_CONTAINER_NAME:-filesend-server-dev}"
  SERVER_WORKSPACE_DIR="${SERVER_WORKSPACE_DIR:-server}"

  APP_DOCKERFILE="${APP_DOCKERFILE:-Dockerfile.sender}"
  APP_IMAGE="${APP_IMAGE:-filesend-app}"

  CONN_MODE="$(normalize_connection_mode "${CONN_MODE_RAW:-ws}")"
  ENCRYPT_MODE="$(normalize_encrypt_mode "${APP_ENCRYPT_RAW:-asymm}")"

  SERVER_HOST="$(extract_host_from_url "${CONN_URL_RAW:-0.0.0.0}")"
  SERVER_PORT="$(extract_port_from_url "${CONN_URL_RAW:-0.0.0.0}" "$CONN_MODE")"
  CONN_URL="$(resolve_filesend_url "$CONN_MODE" "${CONN_URL_RAW:-0.0.0.0}")"

  REPO_ROOT="$(cd "$REPO_ROOT" && pwd -P)"
  SERVER_WORKSPACE_ABS="$(cd "$REPO_ROOT/$SERVER_WORKSPACE_DIR" && pwd -P)"

  GENERATE_CONFIGS_SCRIPT="$REPO_ROOT/generate-configs.sh"
  GENERATE_SECURITY_SCRIPT="$REPO_ROOT/generate-security.sh"

  ROOT_FILESEND_CONFIG="$REPO_ROOT/filesend_config"
  SERVER_CONFIG_PATH="$REPO_ROOT/server/server_config"

  CRYPTO_ROOT="$REPO_ROOT/crypto"
  ASYMM_ROOT="$CRYPTO_ROOT/asymm"
  SYMM_ROOT="$CRYPTO_ROOT/symm"
  CA_DIR="$ASYMM_ROOT/CA"
  CLIENT_SERVER_CRYPTO_DIR="$ASYMM_ROOT/server"
  SERVER_CONFIG_MIRROR_PATH="$CLIENT_SERVER_CRYPTO_DIR/server_config"

  if [[ "$ENCRYPT_MODE" == "symm" ]]; then
    DEVICES_ROOT="$SYMM_ROOT/devices"
  else
    DEVICES_ROOT="$ASYMM_ROOT/devices"
  fi

  mkdir -p "$CA_DIR" "$CLIENT_SERVER_CRYPTO_DIR" "$SYMM_ROOT" "$DEVICES_ROOT"
}

main() {
  parse_args "$@"
  load_config
  resolve_selected_devices

  local incoming_subpath
  incoming_subpath="$(normalize_incoming_subpath "$INCOMING_DIR")"

  ensure_base_configs
  ensure_server_images
  ensure_security_material
  select_complete_dated_bundle
  mirror_client_security_material
  update_root_filesend_config
  update_generated_server_config
  prepare_devices "$incoming_subpath"
}

main "$@"