#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"

die()  { echo "[ERROR] $*" >&2; exit 1; }
warn() { echo "[WARN]  $*" >&2; }
log()  { echo "[INFO]  $*"; }

usage() {
  cat <<EOF
Usage:
  $SCRIPT_NAME [workdir] [--image NAME] [--container NAME] [--force[=all|keys|tls]] [--no-update-env] [--no-update-server-config]

Arguments:
  workdir                      Working directory to operate in (default: current directory)

Runtime options:
  --image NAME                 Docker image used for filesend key generation
                               (or set FILESEND_IMAGE_NAME)
  --container NAME             Running container used for filesend key generation
                               (or set FILESEND_CONTAINER_NAME)

Behavior:
  - Reuses existing usable material by default
  - Repairs stale references in .env and server_config
  - Generates filesend keys via Docker
  - Generates TLS material on the host with openssl
  - Writes into:
      keys/
      certs/
      .env
      server_config

Force options:
  --force                      Same as --force=all
  --force=all                  Regenerate filesend keys and TLS material
  --force=keys                 Regenerate only filesend key material
  --force=tls                  Regenerate only TLS material

Examples:
  $SCRIPT_NAME
  $SCRIPT_NAME . --image filesend-server-dev
  $SCRIPT_NAME . --image filesend-server-dev --force
  $SCRIPT_NAME . --container filesend-server-dev --force=keys
  $SCRIPT_NAME . --image filesend-server-dev --force=tls --no-update-env
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

for cmd in bash date cp mkdir chmod grep sed find sort tr openssl docker pwd mv rm; do
  require_cmd "$cmd"
done

WORKDIR="."
FORCE_MODE=""
UPDATE_ENV="true"
UPDATE_SERVER_CONFIG="true"

DATE_TAG="$(date +%F)"
CERT_SUBJECT="${CERT_SUBJECT:-/CN=localhost}"
DEVICE_ID_VALUE="${DEVICE_ID_VALUE:-device_id}"

FILESEND_IMAGE_NAME="${FILESEND_IMAGE_NAME:-}"
FILESEND_CONTAINER_NAME="${FILESEND_CONTAINER_NAME:-}"
FILESEND_BIN_IN_RUNTIME="${FILESEND_BIN_IN_RUNTIME:-/opt/filesend/filesend}"

ASYM_PRIVATE_PATH_GEN=""
ASYM_PUBLIC_PATH_GEN=""
SYM_KEY_PATH_GEN=""
CA_KEY_PATH_GEN=""
CA_CERT_PATH_GEN=""
SERVER_KEY_PATH_GEN=""
SERVER_CSR_PATH_GEN=""
SERVER_CERT_PATH_GEN=""
SERVER_EXT_PATH_GEN=""

FOUND_ASYM_PRIVATE_PATH=""
FOUND_ASYM_PUBLIC_PATH=""
FOUND_SYM_KEY_PATH=""
FOUND_CA_CERT_PATH=""
FOUND_SERVER_KEY_PATH=""
FOUND_SERVER_CERT_PATH=""

KEYGEN_BACKEND=""   # container|image

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help|-h)
        usage
        exit 0
        ;;
      --force)
        FORCE_MODE="all"
        ;;
      --force=*)
        FORCE_MODE="${1#--force=}"
        ;;
      --image)
        shift
        [[ $# -gt 0 ]] || die "Missing value for --image"
        FILESEND_IMAGE_NAME="$1"
        ;;
      --image=*)
        FILESEND_IMAGE_NAME="${1#--image=}"
        ;;
      --container)
        shift
        [[ $# -gt 0 ]] || die "Missing value for --container"
        FILESEND_CONTAINER_NAME="$1"
        ;;
      --container=*)
        FILESEND_CONTAINER_NAME="${1#--container=}"
        ;;
      --no-update-env)
        UPDATE_ENV="false"
        ;;
      --no-update-server-config)
        UPDATE_SERVER_CONFIG="false"
        ;;
      -*)
        die "Unknown option: $1"
        ;;
      *)
        if [[ "$WORKDIR" == "." ]]; then
          WORKDIR="$1"
        else
          die "Unexpected argument: $1"
        fi
        ;;
    esac
    shift
  done

  case "$FORCE_MODE" in
    ""|all|keys|tls) ;;
    *) die "Invalid --force value: $FORCE_MODE" ;;
  esac
}

should_force_keys() { [[ "$FORCE_MODE" == "all" || "$FORCE_MODE" == "keys" ]]; }
should_force_tls()  { [[ "$FORCE_MODE" == "all" || "$FORCE_MODE" == "tls" ]]; }

ensure_dir() {
  local dir="$1"
  [[ -d "$dir" ]] || mkdir -p "$dir"
}

ensure_env_file() {
  local env_file="${1:-.env}"
  if [[ -f "$env_file" ]]; then
    return 0
  fi
  if [[ -f "server/.env" ]]; then
    cp "server/.env" "$env_file"
    log "Copied server/.env -> $env_file"
  else
    : > "$env_file"
    log "Created empty $env_file"
  fi
}

update_ini_value() {
  local file="$1" key="$2" value="$3"

  [[ -f "$file" ]] || { warn "Config file not found: $file"; return 1; }

  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
  else
    printf '\n%s = %s\n' "$key" "$value" >> "$file"
  fi
}

update_env_export() {
  local file="$1" var="$2" value="$3"

  [[ -f "$file" ]] || touch "$file"

  if grep -Eq "^[[:space:]]*export[[:space:]]+${var}=" "$file"; then
    sed -i -E "s|^[[:space:]]*export[[:space:]]+${var}=.*$|export ${var}=${value}|" "$file"
  elif grep -Eq "^[[:space:]]*${var}=" "$file"; then
    sed -i -E "s|^[[:space:]]*${var}=.*$|export ${var}=${value}|" "$file"
  else
    printf '\nexport %s=%s\n' "$var" "$value" >> "$file"
  fi
}

read_config_value() {
  local file="$1" key="$2"
  sed -n -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$/\1/p" "$file" | tail -n1
}

read_env_export_value() {
  local file="$1" var="$2"
  sed -n -E "s/^[[:space:]]*(export[[:space:]]+)?${var}=(.*)[[:space:]]*$/\2/p" "$file" | tail -n1
}

trim_wrapping_quotes() {
  local v="$1"
  if [[ "$v" == \"*\" && "$v" == *\" ]]; then
    v="${v#\"}"
    v="${v%\"}"
  elif [[ "$v" == \'*\' && "$v" == *\' ]]; then
    v="${v#\'}"
    v="${v%\'}"
  fi
  printf '%s' "$v"
}

resolve_path_from_file() {
  local base_file="$1" raw_path="$2"

  raw_path="$(trim_wrapping_quotes "$raw_path")"
  [[ -n "$raw_path" ]] || return 1

  if [[ "$raw_path" = /* ]]; then
    printf '%s\n' "$raw_path"
    return 0
  fi

  local base_dir
  base_dir="$(cd -- "$(dirname -- "$base_file")" 2>/dev/null && pwd -P)" || return 1
  printf '%s/%s\n' "$base_dir" "$raw_path"
}

path_from_file_exists() {
  local base_file="$1" raw_path="$2" resolved=""
  resolved="$(resolve_path_from_file "$base_file" "$raw_path" || true)"
  [[ -n "$resolved" && -f "$resolved" ]]
}

_filename_matches_tokens() {
  local filename="$1"
  shift

  local normalized
  normalized="$(
    printf '%s' "$filename" \
      | tr '[:upper:]' '[:lower:]' \
      | sed -E 's/[^a-z0-9]+/ /g'
  )"

  local token=""
  for token in "$@"; do
    local t
    t="$(printf '%s' "$token" | tr '[:upper:]' '[:lower:]')"
    [[ " $normalized " == *" $t "* ]] || return 1
  done
  return 0
}

find_security_file() {
  local search_dir="$1"
  shift
  [[ -d "$search_dir" ]] || return 1

  local path=""
  while IFS= read -r -d '' path; do
    if _filename_matches_tokens "$(basename "$path")" "$@"; then
      printf '%s\n' "$path"
      return 0
    fi
  done < <(find "$search_dir" -type f -print0 2>/dev/null | sort -z)

  return 1
}

select_security_material() {
  local key_dir="${1:-keys}"
  local cert_dir="${2:-certs}"

  FOUND_ASYM_PRIVATE_PATH="$(find_security_file "$key_dir" pr key || true)"
  FOUND_ASYM_PUBLIC_PATH="$(find_security_file "$key_dir" pub key || true)"
  FOUND_SYM_KEY_PATH="$(find_security_file "$key_dir" sym key || true)"

  FOUND_CA_CERT_PATH="$(find_security_file "$cert_dir" ca cert || true)"
  FOUND_SERVER_KEY_PATH="$(find_security_file "$key_dir" server key || true)"
  FOUND_SERVER_CERT_PATH="$(find_security_file "$cert_dir" server crt || true)"

  if [[ -z "$FOUND_SERVER_CERT_PATH" ]]; then
    FOUND_SERVER_CERT_PATH="$(find_security_file "$cert_dir" server cert || true)"
  fi
}

keys_missing() {
  select_security_material "keys" "certs"
  [[ -n "$FOUND_ASYM_PRIVATE_PATH" && -f "$FOUND_ASYM_PRIVATE_PATH" ]] || return 0
  if [[ -n "$FOUND_ASYM_PUBLIC_PATH" && -f "$FOUND_ASYM_PUBLIC_PATH" ]]; then
    return 1
  fi
  if [[ -n "$FOUND_SYM_KEY_PATH" && -f "$FOUND_SYM_KEY_PATH" ]]; then
    return 1
  fi
  return 0
}

tls_missing() {
  select_security_material "keys" "certs"
  [[ -n "$FOUND_CA_CERT_PATH" && -f "$FOUND_CA_CERT_PATH" ]] || return 0
  [[ -n "$FOUND_SERVER_KEY_PATH" && -f "$FOUND_SERVER_KEY_PATH" ]] || return 0
  [[ -n "$FOUND_SERVER_CERT_PATH" && -f "$FOUND_SERVER_CERT_PATH" ]] || return 0
  return 1
}

container_exists() {
  local name="$1"
  docker inspect "$name" >/dev/null 2>&1
}

container_is_running() {
  local name="$1"
  [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" == "true" ]]
}

image_exists() {
  local name="$1"
  docker image inspect "$name" >/dev/null 2>&1
}

container_exec_sh() {
  local script="$1"
  docker exec "$FILESEND_CONTAINER_NAME" sh -lc "$script"
}

select_keygen_backend() {
  KEYGEN_BACKEND=""

  if [[ -n "$FILESEND_CONTAINER_NAME" ]] && container_exists "$FILESEND_CONTAINER_NAME" && container_is_running "$FILESEND_CONTAINER_NAME"; then
    if container_exec_sh "test -x \"$FILESEND_BIN_IN_RUNTIME\""; then
      KEYGEN_BACKEND="container"
      log "Using running container for key generation: $FILESEND_CONTAINER_NAME"
      return 0
    fi
    warn "Running container '$FILESEND_CONTAINER_NAME' does not have executable: $FILESEND_BIN_IN_RUNTIME"
  fi

  if [[ -n "$FILESEND_IMAGE_NAME" ]]; then
    image_exists "$FILESEND_IMAGE_NAME" || die "Image not found: $FILESEND_IMAGE_NAME"

    if docker run --rm --entrypoint sh "$FILESEND_IMAGE_NAME" -lc "test -x \"$FILESEND_BIN_IN_RUNTIME\""; then
      KEYGEN_BACKEND="image"
      log "Using Docker image for key generation: $FILESEND_IMAGE_NAME"
      return 0
    fi

    die "filesend binary not found in image '$FILESEND_IMAGE_NAME' at '$FILESEND_BIN_IN_RUNTIME'"
  fi

  die "No usable filesend key generation backend found. Pass --image NAME or a running --container NAME."
}

run_filesend_keygen() {
  local mode="$1"
  local host_outdir="$2"
  local host_outdir_abs

  ensure_dir "$host_outdir"
  host_outdir_abs="$(cd "$host_outdir" && pwd -P)"

  case "$KEYGEN_BACKEND" in
    container)
      local container_tmp_root="/tmp/filesend-keygen-${DATE_TAG}-$$-${mode}"
      local container_outdir="${container_tmp_root}/out"

      log "Generating ${mode} key material inside running container"
      container_exec_sh "
        set -eu
        rm -rf \"$container_tmp_root\"
        mkdir -p \"$container_outdir\"
        cd \"$container_outdir\"
        \"$FILESEND_BIN_IN_RUNTIME\" keygen \"--${mode}\"
      "

      docker cp "${FILESEND_CONTAINER_NAME}:${container_outdir}/." "$host_outdir_abs/" \
        || die "Failed to copy generated ${mode} keys from container"

      container_exec_sh "rm -rf \"$container_tmp_root\"" >/dev/null 2>&1 || true
      ;;
    image)
      log "Generating ${mode} key material inside temporary container from image"
      docker run --rm \
        -v "${host_outdir_abs}:/out" \
        --entrypoint sh \
        "$FILESEND_IMAGE_NAME" \
        -lc "
          set -eu
          cd /out
          rm -f pr_key.bin pub_key.bin sym_key.bin
          \"$FILESEND_BIN_IN_RUNTIME\" keygen \"--${mode}\"
        " \
        || die "Failed to generate ${mode} keys using image '$FILESEND_IMAGE_NAME'"
      ;;
    *)
      die "Internal error: unknown keygen backend: $KEYGEN_BACKEND"
      ;;
  esac
}

generate_keys_material() {
  select_keygen_backend
  ensure_dir "keys"

  local host_tmp_root=".tmp-keys-${DATE_TAG}-$$"
  local asym_tmp_dir="${host_tmp_root}/asymmetric"
  local sym_tmp_dir="${host_tmp_root}/symmetric"

  rm -rf -- "$host_tmp_root"
  mkdir -p "$asym_tmp_dir" "$sym_tmp_dir"

  run_filesend_keygen "asymmetric" "$asym_tmp_dir"
  run_filesend_keygen "symmetric" "$sym_tmp_dir"

  ASYM_PRIVATE_PATH_GEN="keys/pr_key-${DATE_TAG}.bin"
  ASYM_PUBLIC_PATH_GEN="keys/pub_key-${DATE_TAG}.bin"
  SYM_KEY_PATH_GEN="keys/sym_key-${DATE_TAG}.bin"

  [[ -f "${asym_tmp_dir}/pr_key.bin" ]]  || die "Missing generated file: ${asym_tmp_dir}/pr_key.bin"
  [[ -f "${asym_tmp_dir}/pub_key.bin" ]] || die "Missing generated file: ${asym_tmp_dir}/pub_key.bin"
  [[ -f "${sym_tmp_dir}/sym_key.bin" ]]  || die "Missing generated file: ${sym_tmp_dir}/sym_key.bin"

  mv -f "${asym_tmp_dir}/pr_key.bin"  "$ASYM_PRIVATE_PATH_GEN"
  mv -f "${asym_tmp_dir}/pub_key.bin" "$ASYM_PUBLIC_PATH_GEN"
  mv -f "${sym_tmp_dir}/sym_key.bin"  "$SYM_KEY_PATH_GEN"

  log "Created $ASYM_PRIVATE_PATH_GEN"
  log "Created $ASYM_PUBLIC_PATH_GEN"
  log "Created $SYM_KEY_PATH_GEN"

  rm -rf -- "$host_tmp_root"
}

generate_tls_material() {
  ensure_dir "keys"
  ensure_dir "certs"

  CA_KEY_PATH_GEN="keys/ca-${DATE_TAG}.key"
  CA_CERT_PATH_GEN="certs/ca_cert-${DATE_TAG}.pem"
  SERVER_KEY_PATH_GEN="keys/server-${DATE_TAG}.key"
  SERVER_CSR_PATH_GEN="certs/server-${DATE_TAG}.csr"
  SERVER_CERT_PATH_GEN="certs/server-${DATE_TAG}.crt"
  SERVER_EXT_PATH_GEN="certs/server_ext-${DATE_TAG}.cnf"

  if [[ ! -f "$CA_KEY_PATH_GEN" ]]; then
    openssl genrsa -out "$CA_KEY_PATH_GEN" 4096
    log "Created $CA_KEY_PATH_GEN"
  fi

  if [[ ! -f "$CA_CERT_PATH_GEN" ]]; then
    openssl req -x509 -new -nodes \
      -key "$CA_KEY_PATH_GEN" \
      -sha256 -days 3650 \
      -out "$CA_CERT_PATH_GEN" \
      -subj "/CN=Test CA ${DATE_TAG}"
    log "Created $CA_CERT_PATH_GEN"
  fi

  if [[ ! -f "$SERVER_KEY_PATH_GEN" ]]; then
    openssl genrsa -out "$SERVER_KEY_PATH_GEN" 2048
    log "Created $SERVER_KEY_PATH_GEN"
  fi

  if [[ ! -f "$SERVER_CSR_PATH_GEN" ]]; then
    openssl req -new \
      -key "$SERVER_KEY_PATH_GEN" \
      -out "$SERVER_CSR_PATH_GEN" \
      -subj "$CERT_SUBJECT"
    log "Created $SERVER_CSR_PATH_GEN"
  fi

  cat > "$SERVER_EXT_PATH_GEN" <<EOF
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF
  log "Wrote $SERVER_EXT_PATH_GEN"

  if [[ ! -f "$SERVER_CERT_PATH_GEN" ]]; then
    openssl x509 -req \
      -in "$SERVER_CSR_PATH_GEN" \
      -CA "$CA_CERT_PATH_GEN" \
      -CAkey "$CA_KEY_PATH_GEN" \
      -CAcreateserial \
      -out "$SERVER_CERT_PATH_GEN" \
      -days 365 \
      -sha256 \
      -extfile "$SERVER_EXT_PATH_GEN"
    log "Created $SERVER_CERT_PATH_GEN"
  fi
}

env_needs_security_update() {
  local env_file="$1"
  [[ -f "$env_file" ]] || return 0

  local pub_key_path="" sym_key_path="" cert_path="" pr_key_path=""
  pub_key_path="$(read_env_export_value "$env_file" "PUB_KEY_PATH" || true)"
  sym_key_path="$(read_env_export_value "$env_file" "SYM_KEY_PATH" || true)"
  cert_path="$(read_env_export_value "$env_file" "CERT_PATH" || true)"
  pr_key_path="$(read_env_export_value "$env_file" "PR_KEY_PATH" || true)"

  path_from_file_exists "$env_file" "$cert_path" || return 0
  path_from_file_exists "$env_file" "$pr_key_path" || return 0

  if path_from_file_exists "$env_file" "$pub_key_path"; then
    return 1
  fi
  if path_from_file_exists "$env_file" "$sym_key_path"; then
    return 1
  fi
  return 0
}

config_needs_security_update() {
  local cfg="$1"
  [[ -f "$cfg" ]] || return 0

  local cert_path="" key_path=""
  cert_path="$(read_config_value "$cfg" "cert_path" || true)"
  key_path="$(read_config_value "$cfg" "key_path" || true)"

  path_from_file_exists "$cfg" "$cert_path" || return 0
  path_from_file_exists "$cfg" "$key_path" || return 0

  return 1
}

update_server_config_security() {
  local cfg="${1:-server_config}"
  [[ -f "$cfg" ]] || { warn "No $cfg found; skipped security config update"; return 0; }

  update_ini_value "$cfg" "cert_path" "$SERVER_CERT_PATH_GEN"
  update_ini_value "$cfg" "key_path" "$SERVER_KEY_PATH_GEN"

  log "Updated $cfg"
}

update_dotenv_security() {
  local env_file="${1:-.env}"

  ensure_env_file "$env_file"

  update_env_export "$env_file" "PUB_KEY_PATH" "$ASYM_PUBLIC_PATH_GEN"
  update_env_export "$env_file" "SYM_KEY_PATH" "$SYM_KEY_PATH_GEN"
  update_env_export "$env_file" "CERT_PATH" "$CA_CERT_PATH_GEN"
  update_env_export "$env_file" "PR_KEY_PATH" "$ASYM_PRIVATE_PATH_GEN"

  local current_device_id=""
  current_device_id="$(read_env_export_value "$env_file" "DEVICE_ID" || true)"
  if [[ -z "$current_device_id" ]]; then
    update_env_export "$env_file" "DEVICE_ID" "$DEVICE_ID_VALUE"
  fi

  log "Updated $env_file"
}

main() {
  parse_args "$@"

  [[ -d "$WORKDIR" ]] || die "Working directory not found: $WORKDIR"
  cd "$WORKDIR"

  log "Working directory: $(pwd)"

  ensure_dir "keys"
  ensure_dir "certs"

  local need_gen_keys=0
  local need_gen_tls=0
  local need_cfg_update=0
  local need_env_update=0

  if should_force_keys || keys_missing; then
    need_gen_keys=1
  fi
  if should_force_tls || tls_missing; then
    need_gen_tls=1
  fi

  if [[ "$UPDATE_SERVER_CONFIG" == "true" ]] && config_needs_security_update "server_config"; then
    need_cfg_update=1
  fi
  if [[ "$UPDATE_ENV" == "true" ]] && env_needs_security_update ".env"; then
    need_env_update=1
  fi

  if [[ "$need_gen_keys" == "1" ]]; then
    log "Generating filesend key material"
    generate_keys_material
  fi

  if [[ "$need_gen_tls" == "1" ]]; then
    log "Generating TLS material"
    generate_tls_material
  fi

  if [[ "$need_gen_keys" != "1" || "$need_gen_tls" != "1" ]]; then
    select_security_material "keys" "certs"
    [[ -z "$ASYM_PRIVATE_PATH_GEN" ]] && ASYM_PRIVATE_PATH_GEN="${FOUND_ASYM_PRIVATE_PATH}"
    [[ -z "$ASYM_PUBLIC_PATH_GEN"  ]] && ASYM_PUBLIC_PATH_GEN="${FOUND_ASYM_PUBLIC_PATH}"
    [[ -z "$SYM_KEY_PATH_GEN"      ]] && SYM_KEY_PATH_GEN="${FOUND_SYM_KEY_PATH}"
    [[ -z "$CA_CERT_PATH_GEN"      ]] && CA_CERT_PATH_GEN="${FOUND_CA_CERT_PATH}"
    [[ -z "$SERVER_KEY_PATH_GEN"   ]] && SERVER_KEY_PATH_GEN="${FOUND_SERVER_KEY_PATH}"
    [[ -z "$SERVER_CERT_PATH_GEN"  ]] && SERVER_CERT_PATH_GEN="${FOUND_SERVER_CERT_PATH}"
  fi

  if [[ "$need_gen_keys" == "1" || "$need_gen_tls" == "1" ]]; then
    need_cfg_update=1
    need_env_update=1
  fi

  if [[ "$UPDATE_SERVER_CONFIG" == "true" && "$need_cfg_update" == "1" ]]; then
    update_server_config_security "server_config"
  fi
  if [[ "$UPDATE_ENV" == "true" && "$need_env_update" == "1" ]]; then
    update_dotenv_security ".env"
  fi

  if [[ "$need_gen_keys" != "1" && "$need_gen_tls" != "1" &&
        "$need_cfg_update" != "1" && "$need_env_update" != "1" ]]; then
    log "Existing security material and references look usable; no update needed"
  fi

  cat <<EOF

Security setup completed.

Detected / generated:
  asymmetric private key: ${ASYM_PRIVATE_PATH_GEN:-<none>}
  asymmetric public key : ${ASYM_PUBLIC_PATH_GEN:-<none>}
  symmetric key         : ${SYM_KEY_PATH_GEN:-<none>}
  CA certificate        : ${CA_CERT_PATH_GEN:-<none>}
  server key            : ${SERVER_KEY_PATH_GEN:-<none>}
  server certificate    : ${SERVER_CERT_PATH_GEN:-<none>}

EOF
}

main "$@"