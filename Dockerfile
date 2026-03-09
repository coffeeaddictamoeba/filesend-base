# Build: docker build -t filesend-app . 

# Run: 
# docker run --rm -it \
#   --name filesend-dev \
#   --user "$(id -u):$(id -g)" \
#   --network=host \
#   -v "$(pwd):/workspace" \
#   -w /workspace \
#   filesend-app

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++ \
    make \
    cmake \
    pkg-config \
    gdb \
    nano \
    less \
    bash \
    ca-certificates \
    openssl \
    libssl-dev \
    libsodium-dev \
    libcurl4-openssl-dev \
    libzip-dev \
    libarchive-dev \
    libboost-all-dev \
    zip \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

ARG USER_ID=1000
ARG GROUP_ID=1000
ARG USERNAME=user

WORKDIR /workspace

RUN set -eux; \
    EXISTING_GROUP="$(getent group ${GROUP_ID} | cut -d: -f1 || true)"; \
    if [ -z "$EXISTING_GROUP" ]; then \
        groupadd -g ${GROUP_ID} ${USERNAME}; \
        EXISTING_GROUP="${USERNAME}"; \
    fi; \
    EXISTING_USER="$(getent passwd ${USER_ID} | cut -d: -f1 || true)"; \
    if [ -z "$EXISTING_USER" ]; then \
        useradd -m -u ${USER_ID} -g ${GROUP_ID} -s /bin/bash ${USERNAME}; \
        EXISTING_USER="${USERNAME}"; \
    fi; \
    mkdir -p /workspace/incoming_files; \
    chown -R ${USER_ID}:${GROUP_ID} /workspace

USER ${USER_ID}:${GROUP_ID}

CMD ["/bin/bash"]