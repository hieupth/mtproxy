ARG BASE_IMAGE=debian

FROM ${BASE_IMAGE} AS build
# MTproxy version
ARG MTPROXY_VERSION=3.0.5
# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      libssl-dev \
      zlib1g-dev \
      curl \
      git \
      ca-certificates
# Build from source
RUN git clone https://github.com/GetPageSpeed/MTProxy /src && \
    cd /src && \
    make clean && make

FROM ${BASE_IMAGE}
# Install wireguard
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      libssl3 \
      zlib1g \
      curl \
      tini \
      xxd \
      jq \
      procps \
      dnsutils \
      coreutils \
      ca-certificates \
      wireguard-tools \
      iproute2 \
      iptables \
      openresolv \
      iputils-ping && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
# Create non-root user for security
RUN groupadd -r -g 1000 mtproxy \
    && useradd -r -u 1000 -g mtproxy -d /opt/mtproxy -s /bin/bash mtproxy
# Copy from build stage
COPY --from=build /src/objs/bin /opt/mtproxy
WORKDIR /opt/mtproxy
# Entrypoint
COPY entrypoint.sh /opt/mtproxy/entrypoint.sh
ENTRYPOINT ["tini", "--"]
CMD ["/opt/mtproxy/entrypoint.sh"]
