# Runtime image for the standalone Socketlink server.
# Build the binary first (WSL/Linux: `make -j$(nproc)`), copy it here, then:
#   cp build/socketlink docker/socketlink
#   docker build -t sl-server docker/
#   docker run -d --name sl-server --cpus=1 --memory=1g \
#     --ulimit nofile=1048576:1048576 -p 8080:8080 -e SL_THREADS=1 sl-server
#
# Plaintext HTTP/WS on 8080 (TLS terminates at the load balancer in front).
# LMDB lives in the container at /app/messages_db (mount a volume to persist).
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3t64 zlib1g liblmdb0 libtbb12 libmysqlclient21 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY socketlink /app/socketlink
RUN mkdir -p /app/messages_db

EXPOSE 8080
ENV SL_LOG_LEVEL=info

CMD ["/app/socketlink"]
