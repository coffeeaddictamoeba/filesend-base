# Build (run from filesend-base repo root):
# docker build \
#   -f examples/Dockerfile \
#   --build-arg USER_UID="$(id -u)" \
#   --build-arg USER_GID="$(id -g)" \
#   -t filesend-server-dev .

# Run (run from filesend-base/examples and set server mode; either WS or HTTP; WS preferred):
# docker run --rm -it \
#   -p 8444:8444 \
#   -v "$PWD:/workspace" \
#   -e SERVER_MODE=ws \
#   filesend-server-dev

# Inside the container (if running as bash):
# source .venv/bin/activate
# set -a && source .env && set +a
# python runserver_ws.py  # OR python runserver_https.py (if available)

FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++ \
    make \
    cmake \
    pkg-config \
    bash \
    ca-certificates \
    openssl \
    libssl-dev \
    libsodium-dev \
    libboost-all-dev \
#   libcurl4-openssl-dev   # if HTTP
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Compile minimal filesend binary to decrypt & respond
COPY Makefile ./Makefile
COPY include ./include
COPY src ./src

# NOTE: FILESEND_PROFILE_MINIMAL_WS does NOT support HTTP connection. 
# To enable it, change PROFILE=MINIMAL to PROFILE=CUSTOM and manually add -lcurl to the flags (ignore the remaining ones, they are not for server)
# Also set FILESEND_ENABLE_HTTP flag to 1 in filesend-base/include/build_fetures.h (set others except FILESEND_ENABLE_WS to 0)
RUN make clean && make PROFILE=MINIMAL_WS && ldd bin/filesend

FROM python:3.12-slim

ARG USER_NAME=dev
ARG USER_UID=1000
ARG USER_GID=1000

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    WORKDIR=/workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    openssl \
    libsodium23 \
    libssl3 \
#   libcurl4 # for HTTP
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid "${USER_GID}" "${USER_NAME}" \
    && useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash "${USER_NAME}"

WORKDIR ${WORKDIR}

COPY --from=builder /build/bin/filesend /opt/filesend/filesend
COPY examples/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /opt/filesend/filesend /usr/local/bin/docker-entrypoint.sh

USER ${USER_NAME}

EXPOSE 8080

# Entrypoint helps to configure all the security materials for testing,
# including keys (symmetric & asymmetric (public/private)), server certificates, etc.

# If sender device lacks security material, this is what should be copied:
#    - examples/certs/ca-cert-YYYY-MM-DD.pem
#    - examples/keys/pub_key-YYYY-MM-DD.bin (if asymmetric; do NOT copy the private key to sender)
#    - examples/keys/sym_key-YYYY-MM-DD.bin (if symmetric)
# Everything else is for server's security

# Set the proper values in filesend_config after copying
# On the other hand, as server generates all the security material, it automatically substitutes the values into .env and server_config.

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["server"]