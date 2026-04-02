#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${WORKDIR:-/workspace}"
SERVER_MODE="${SERVER_MODE:-ws}"                      # ws | https
SERVER_PORT="${SERVER_PORT:-8444}"                    # server port
AUTO_BOOTSTRAP="${AUTO_BOOTSTRAP:-1}"                 # 1=yes, 0=no
AUTO_GENERATE_SECURITY="${AUTO_GENERATE_SECURITY:-1}" # 1=yes, 0=no
CERT_SUBJECT="${CERT_SUBJECT:-/CN=localhost}"
DEVICE_ID_VALUE="${DEVICE_ID_VALUE:-device_id}"
DATE_TAG="$(date +%F)"

cd "${WORKDIR}"

echo "Working directory: ${WORKDIR}"
echo "Server mode: ${SERVER_MODE}"
echo "Server port: ${SERVER_PORT}"

copy_if_missing() {
  local src="$1"
  local dst="$2"

  if [[ -f "${src}" && ! -f "${dst}" ]]; then
    cp "${src}" "${dst}"
    echo "Copied ${src} -> ${dst}"
  fi
}

ensure_dir() {
  local dir="$1"
  [[ -d "$dir" ]] || mkdir -p "$dir"
}

prepare_temp_input() {
  local file="$1"
  printf 'bootstrap-%s\n' "${DATE_TAG}" > "${file}"
}

ensure_filesend_binary() {
  local baked_bin="/opt/filesend/filesend"
  local dst_dir="bin"
  local dst_file="${dst_dir}/filesend"

  if [[ ! -f "${baked_bin}" ]]; then
    echo "Baked filesend binary not found at: ${baked_bin}"
    return 1
  fi

  ensure_dir "${dst_dir}"
  cp -f "${baked_bin}" "${dst_file}"
  chmod +x "${dst_file}"

  echo "Initialized filesend binary at: ${dst_file}"
}

update_ini_value() {
  local file="$1"
  local key="$2"
  local value="$3"

  if [[ ! -f "$file" ]]; then
    echo "Config file not found: $file"
    return 1
  fi

  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
  else
    printf '\n%s = %s\n' "$key" "$value" >> "$file"
  fi
}

update_env_export() {
  local file="$1"
  local var="$2"
  local value="$3"

  if [[ ! -f "$file" ]]; then
    touch "$file"
  fi

  if grep -Eq "^[[:space:]]*export[[:space:]]+${var}=" "$file"; then
    sed -i -E "s|^[[:space:]]*export[[:space:]]+${var}=.*$|export ${var}=${value}|" "$file"
  elif grep -Eq "^[[:space:]]*${var}=" "$file"; then
    sed -i -E "s|^[[:space:]]*${var}=.*$|export ${var}=${value}|" "$file"
  else
    printf '\nexport %s=%s\n' "$var" "$value" >> "$file"
  fi
}

read_config_value() {
  local file="$1"
  local key="$2"
  sed -n -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$/\1/p" "$file" | tail -n1
}

read_env_export_value() {
  local file="$1"
  local var="$2"
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
  local base_file="$1"
  local raw_path="$2"

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
  local base_file="$1"
  local raw_path="$2"
  local resolved=""

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

  if [[ -z "${FOUND_SERVER_CERT_PATH}" ]]; then
    FOUND_SERVER_CERT_PATH="$(find_security_file "$cert_dir" server cert || true)"
  fi

  export FOUND_ASYM_PRIVATE_PATH
  export FOUND_ASYM_PUBLIC_PATH
  export FOUND_SYM_KEY_PATH
  export FOUND_CA_CERT_PATH
  export FOUND_SERVER_KEY_PATH
  export FOUND_SERVER_CERT_PATH
}

# Returns:
#   0 => generation IS needed
#   1 => generation is NOT needed
security_material_missing() {
  select_security_material "keys" "certs"

  [[ -n "${FOUND_ASYM_PRIVATE_PATH}" && -f "${FOUND_ASYM_PRIVATE_PATH}" ]] || return 0
  [[ -n "${FOUND_CA_CERT_PATH}" && -f "${FOUND_CA_CERT_PATH}" ]] || return 0
  [[ -n "${FOUND_SERVER_KEY_PATH}" && -f "${FOUND_SERVER_KEY_PATH}" ]] || return 0
  [[ -n "${FOUND_SERVER_CERT_PATH}" && -f "${FOUND_SERVER_CERT_PATH}" ]] || return 0

  if [[ -n "${FOUND_ASYM_PUBLIC_PATH}" && -f "${FOUND_ASYM_PUBLIC_PATH}" ]]; then
    return 1
  fi

  if [[ -n "${FOUND_SYM_KEY_PATH}" && -f "${FOUND_SYM_KEY_PATH}" ]]; then
    return 1
  fi

  return 0
}

generate_filesend_keys() {
  local mode="$1"     # asymmetric | symmetric
  local outdir="$2"

  ensure_dir "$outdir"

  local tmpfile="${outdir}/myfile.tmp"
  prepare_temp_input "$tmpfile"

  echo "Generating ${mode} key material via filesend in ${outdir}"

  (
    cd "$outdir"

    unset PUB_KEY_PATH || true
    unset PR_KEY_PATH || true
    unset SYM_KEY_PATH || true

    "../../bin/./filesend" encrypt myfile.tmp "--${mode}"
  )

  rm -f "$tmpfile"
}

generate_security() {
  ensure_dir "certs"
  ensure_dir "keys"
  ensure_dir ".tmp-keys"

  local asym_tmp_dir=".tmp-keys/asymmetric-${DATE_TAG}"
  local sym_tmp_dir=".tmp-keys/symmetric-${DATE_TAG}"

  rm -rf "${asym_tmp_dir}" "${sym_tmp_dir}"
  ensure_dir "${asym_tmp_dir}"
  ensure_dir "${sym_tmp_dir}"

  generate_filesend_keys "asymmetric" "${asym_tmp_dir}"
  generate_filesend_keys "symmetric" "${sym_tmp_dir}"

  ASYM_PRIVATE_PATH_GEN="keys/pr_key-${DATE_TAG}.bin"
  ASYM_PUBLIC_PATH_GEN="keys/pub_key-${DATE_TAG}.bin"
  SYM_KEY_PATH_GEN="keys/sym_key-${DATE_TAG}.bin"

  if [[ -f "${asym_tmp_dir}/pr_key.bin" ]]; then
    mv -f "${asym_tmp_dir}/pr_key.bin" "${ASYM_PRIVATE_PATH_GEN}"
    echo "Created ${ASYM_PRIVATE_PATH_GEN}"
  else
    echo "Missing generated file: ${asym_tmp_dir}/pr_key.bin"
    return 1
  fi

  if [[ -f "${asym_tmp_dir}/pub_key.bin" ]]; then
    mv -f "${asym_tmp_dir}/pub_key.bin" "${ASYM_PUBLIC_PATH_GEN}"
    echo "Created ${ASYM_PUBLIC_PATH_GEN}"
  else
    echo "Missing generated file: ${asym_tmp_dir}/pub_key.bin"
    return 1
  fi

  if [[ -f "${sym_tmp_dir}/sym_key.bin" ]]; then
    mv -f "${sym_tmp_dir}/sym_key.bin" "${SYM_KEY_PATH_GEN}"
    echo "Created ${SYM_KEY_PATH_GEN}"
  else
    echo "Missing generated file: ${sym_tmp_dir}/sym_key.bin"
    return 1
  fi

  rm -rf "${asym_tmp_dir}" "${sym_tmp_dir}"

  CA_KEY_PATH_GEN="keys/ca-${DATE_TAG}.key"
  CA_CERT_PATH_GEN="certs/ca_cert-${DATE_TAG}.pem"

  SERVER_KEY_PATH_GEN="keys/server-${DATE_TAG}.key"
  SERVER_CSR_PATH_GEN="certs/server-${DATE_TAG}.csr"
  SERVER_CERT_PATH_GEN="certs/server-${DATE_TAG}.crt"
  SERVER_EXT_PATH_GEN="certs/server_ext-${DATE_TAG}.cnf"

  if [[ ! -f "${CA_KEY_PATH_GEN}" ]]; then
    openssl genrsa -out "${CA_KEY_PATH_GEN}" 4096
    echo "Created ${CA_KEY_PATH_GEN}"
  else
    echo "Exists: ${CA_KEY_PATH_GEN}"
  fi

  if [[ ! -f "${CA_CERT_PATH_GEN}" ]]; then
    openssl req -x509 -new -nodes \
      -key "${CA_KEY_PATH_GEN}" \
      -sha256 -days 3650 \
      -out "${CA_CERT_PATH_GEN}" \
      -subj "/CN=Test CA ${DATE_TAG}"
    echo "Created ${CA_CERT_PATH_GEN}"
  else
    echo "Exists: ${CA_CERT_PATH_GEN}"
  fi

  if [[ ! -f "${SERVER_KEY_PATH_GEN}" ]]; then
    openssl genrsa -out "${SERVER_KEY_PATH_GEN}" 2048
    echo "Created ${SERVER_KEY_PATH_GEN}"
  else
    echo "Exists: ${SERVER_KEY_PATH_GEN}"
  fi

  if [[ ! -f "${SERVER_CSR_PATH_GEN}" ]]; then
    openssl req -new \
      -key "${SERVER_KEY_PATH_GEN}" \
      -out "${SERVER_CSR_PATH_GEN}" \
      -subj "${CERT_SUBJECT}"
    echo "Created ${SERVER_CSR_PATH_GEN}"
  else
    echo "Exists: ${SERVER_CSR_PATH_GEN}"
  fi

  cat > "${SERVER_EXT_PATH_GEN}" <<EOF
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF
  echo "Wrote ${SERVER_EXT_PATH_GEN}"

  if [[ ! -f "${SERVER_CERT_PATH_GEN}" ]]; then
    openssl x509 -req \
      -in "${SERVER_CSR_PATH_GEN}" \
      -CA "${CA_CERT_PATH_GEN}" \
      -CAkey "${CA_KEY_PATH_GEN}" \
      -CAcreateserial \
      -out "${SERVER_CERT_PATH_GEN}" \
      -days 365 \
      -sha256 \
      -extfile "${SERVER_EXT_PATH_GEN}"
    echo "Created ${SERVER_CERT_PATH_GEN}"
  else
    echo "Exists: ${SERVER_CERT_PATH_GEN}"
  fi

  # Refresh detected paths after generation so update_* uses actual files.
  select_security_material "keys" "certs"
  ASYM_PRIVATE_PATH_GEN="${FOUND_ASYM_PRIVATE_PATH}"
  ASYM_PUBLIC_PATH_GEN="${FOUND_ASYM_PUBLIC_PATH}"
  SYM_KEY_PATH_GEN="${FOUND_SYM_KEY_PATH}"
  CA_CERT_PATH_GEN="${FOUND_CA_CERT_PATH}"
  SERVER_KEY_PATH_GEN="${FOUND_SERVER_KEY_PATH}"
  SERVER_CERT_PATH_GEN="${FOUND_SERVER_CERT_PATH}"
}

# Returns:
#   0 => .env should be updated
#   1 => .env looks usable as-is
env_needs_security_update() {
  local env_file="$1"
  [[ -f "$env_file" ]] || return 0

  local pub_key_path=""
  local sym_key_path=""
  local cert_path=""
  local pr_key_path=""

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

# Returns:
#   0 => config should be updated
#   1 => config looks usable as-is
config_needs_security_update() {
  local cfg="$1"
  [[ -f "$cfg" ]] || return 0

  local cert_path=""
  local key_path=""

  cert_path="$(read_config_value "$cfg" "cert_path" || true)"
  key_path="$(read_config_value "$cfg" "key_path" || true)"

  path_from_file_exists "$cfg" "$cert_path" || return 0
  path_from_file_exists "$cfg" "$key_path" || return 0

  return 1
}

update_server_config_security() {
  local cfg="${1:-server_config}"

  if [[ ! -f "$cfg" ]]; then
    echo "No ${cfg} found; skipped security config update"
    return 0
  fi

  update_ini_value "$cfg" "cert_path" "${SERVER_CERT_PATH_GEN}"
  update_ini_value "$cfg" "key_path" "${SERVER_KEY_PATH_GEN}"

  echo "Updated ${cfg}:"
  echo "  cert_path = ${SERVER_CERT_PATH_GEN}"
  echo "  key_path  = ${SERVER_KEY_PATH_GEN}"
}

update_dotenv_security() {
  local env_file="${1:-.env}"

  update_env_export "$env_file" "PUB_KEY_PATH" "${ASYM_PUBLIC_PATH_GEN}"
  update_env_export "$env_file" "SYM_KEY_PATH" "${SYM_KEY_PATH_GEN}"
  update_env_export "$env_file" "CERT_PATH" "${CA_CERT_PATH_GEN}"
  update_env_export "$env_file" "PR_KEY_PATH" "${ASYM_PRIVATE_PATH_GEN}"

  local current_device_id=""
  current_device_id="$(read_env_export_value "$env_file" "DEVICE_ID" || true)"
  if [[ -z "$current_device_id" ]]; then
    update_env_export "$env_file" "DEVICE_ID" "${DEVICE_ID_VALUE}"
  fi

  echo "Updated ${env_file}:"
  echo "  export PUB_KEY_PATH=${ASYM_PUBLIC_PATH_GEN}"
  echo "  export SYM_KEY_PATH=${SYM_KEY_PATH_GEN}"
  echo "  export CERT_PATH=${CA_CERT_PATH_GEN}"
  echo "  export PR_KEY_PATH=${ASYM_PRIVATE_PATH_GEN}"
}

bootstrap_repo() {
  ensure_filesend_binary

  if [[ ! -x "bin/filesend" ]]; then
    echo "bin/filesend is missing or not executable"
    return 1
  fi

  if [[ "${SERVER_MODE}" == "https" ]]; then
    copy_if_missing "examples/runserver_https.py" "runserver_https.py"
  else
    copy_if_missing "examples/runserver_ws.py" "runserver_ws.py"
  fi

  copy_if_missing "examples/.env" ".env"
  copy_if_missing "examples/server_config" "server_config"

  if [[ ! -d ".venv" ]]; then
    python -m venv .venv
    echo "Created virtual environment: .venv"
  else
    echo "Exists: .venv"
  fi

  # shellcheck disable=SC1091
  source .venv/bin/activate

  python -m pip install --upgrade pip
  pip install aiohttp websockets

  echo
  echo "Installed packages:"
  pip list | grep -E 'aiohttp|websockets|pip|setuptools' || true

  if [[ -f ".env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
    echo "Loaded .env"
  else
    echo "No .env found; skipped loading it"
  fi
}

load_runtime_env() {
  if [[ -f ".venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
  else
    echo "Missing virtualenv: .venv/bin/activate"
    return 1
  fi

  if [[ -f ".env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
    echo "Loaded .env"
  else
    echo "No .env found"
  fi
}

start_server() {
  load_runtime_env

  case "${SERVER_MODE}" in
    ws)
      echo "Starting WebSocket server"
      exec python runserver_ws.py
      ;;
    https)
      echo "Starting HTTPS server"
      exec python runserver_https.py
      ;;
    *)
      echo "Unsupported SERVER_MODE: ${SERVER_MODE}"
      exit 1
      ;;
  esac
}

print_help() {
  cat <<'EOF'

Container is ready.

Typical usage:

  source .venv/bin/activate
  set -a && source .env && set +a
  python runserver_ws.py

or:

  source .venv/bin/activate
  set -a && source .env && set +a
  python runserver_https.py

Sender side example:
  bin/./filesend send new_directory/

Notes:
- Generated files are written into the bind-mounted repo, so they appear on your host
- Files use date-based names
- Existing security material is detected from keys/ and certs/
- .env and server_config are patched independently if they contain stale paths

EOF
}

if [[ "${AUTO_BOOTSTRAP}" == "1" ]]; then
  bootstrap_repo
fi

if [[ "${AUTO_GENERATE_SECURITY}" == "1" ]]; then
  NEED_GEN=0
  NEED_CFG_UPDATE=0
  NEED_ENV_UPDATE=0

  # Decide generation from actual material on disk only.
  if security_material_missing; then
    NEED_GEN=1
  fi

  # Decide file refresh independently.
  if config_needs_security_update "server_config"; then
    NEED_CFG_UPDATE=1
  fi

  if env_needs_security_update ".env"; then
    NEED_ENV_UPDATE=1
  fi

  if [[ "${NEED_GEN}" == "1" ]]; then
    echo "Security material missing; generating test security material"
    generate_security

    # Fresh material means references should be refreshed too.
    NEED_CFG_UPDATE=1
    NEED_ENV_UPDATE=1
  else
    # Material exists already; expose discovered paths so update_* can repair stale config.
    select_security_material "keys" "certs"
    ASYM_PRIVATE_PATH_GEN="${FOUND_ASYM_PRIVATE_PATH}"
    ASYM_PUBLIC_PATH_GEN="${FOUND_ASYM_PUBLIC_PATH}"
    SYM_KEY_PATH_GEN="${FOUND_SYM_KEY_PATH}"
    CA_CERT_PATH_GEN="${FOUND_CA_CERT_PATH}"
    SERVER_KEY_PATH_GEN="${FOUND_SERVER_KEY_PATH}"
    SERVER_CERT_PATH_GEN="${FOUND_SERVER_CERT_PATH}"
  fi

  if [[ "${NEED_CFG_UPDATE}" == "1" ]]; then
    echo "Updating security references in server_config"
    update_server_config_security "server_config"
  fi

  if [[ "${NEED_ENV_UPDATE}" == "1" ]]; then
    echo "Updating security references in .env"
    update_dotenv_security ".env"
  fi

  if [[ "${NEED_GEN}" != "1" &&
        "${NEED_CFG_UPDATE}" != "1" &&
        "${NEED_ENV_UPDATE}" != "1" ]]; then
    echo "Existing security material and references look usable; no update needed"
  fi
fi

print_help

case "${1:-server}" in
  server)
    start_server
    ;;
  bash|sh)
    exec "$@"
    ;;
  *)
    exec "$@"
    ;;
esac