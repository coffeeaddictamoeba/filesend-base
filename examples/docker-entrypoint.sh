#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${WORKDIR:-/workspace}"
SERVER_MODE="${SERVER_MODE:-ws}"                       # ws | https
AUTO_BOOTSTRAP="${AUTO_BOOTSTRAP:-1}"                 # 1=yes, 0=no
AUTO_GENERATE_SECURITY="${AUTO_GENERATE_SECURITY:-1}" # 1=yes, 0=no
CERT_SUBJECT="${CERT_SUBJECT:-/CN=localhost}"
DEVICE_ID_VALUE="${DEVICE_ID_VALUE:-device_id}"
DATE_TAG="$(date +%F)"

cd "${WORKDIR}"

echo "Working directory: ${WORKDIR}"
echo "Server mode: ${SERVER_MODE}"

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
      -subj "/CN=localhost"
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
}

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

  [[ -n "$cert_path" && -f "$cert_path" ]] || return 0
  [[ -n "$pr_key_path" && -f "$pr_key_path" ]] || return 0

  # At least one of PUB_KEY_PATH or SYM_KEY_PATH should exist.
  if [[ -n "$pub_key_path" && -f "$pub_key_path" ]]; then
    return 1
  fi

  if [[ -n "$sym_key_path" && -f "$sym_key_path" ]]; then
    return 1
  fi

  return 0
}

config_needs_security_update() {
  local cfg="$1"
  [[ -f "$cfg" ]] || return 0

  local cert_path=""
  local key_path=""

  cert_path="$(read_config_value "$cfg" "cert_path" || true)"
  key_path="$(read_config_value "$cfg" "key_path" || true)"

  [[ -n "$cert_path" && -f "$cert_path" ]] || return 0
  [[ -n "$key_path" && -f "$key_path" ]] || return 0

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
- server_config and .env are patched automatically when referenced security files are missing

EOF
}

if [[ "${AUTO_BOOTSTRAP}" == "1" ]]; then
  bootstrap_repo
fi

if [[ "${AUTO_GENERATE_SECURITY}" == "1" ]]; then
  NEED_GEN=0

  if config_needs_security_update "server_config"; then
    NEED_GEN=1
  fi

  if env_needs_security_update ".env"; then
    NEED_GEN=1
  fi

  if [[ "${NEED_GEN}" == "1" ]]; then
    echo "Security data missing or invalid; generating test security material"
    generate_security
    update_server_config_security "server_config"
    update_dotenv_security ".env"
  else
    echo "Existing security references in server_config and .env look usable; no update needed"
  fi
fi

print_help

exec "$@"