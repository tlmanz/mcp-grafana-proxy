# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/mcp-grafana-proxy ./cmd/mcp-grafana-proxy \
 && mkdir -p /out/data

# Static binary, CA certificates, no shell; runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-grafana-proxy /usr/local/bin/mcp-grafana-proxy
# Owned by the nonroot user so a fresh named volume is writable.
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME /data
EXPOSE 8090 18080
ENTRYPOINT ["/usr/local/bin/mcp-grafana-proxy"]
# Listen on all container interfaces; docker-compose.yml publishes the ports
# on the host's 127.0.0.1 only.
CMD ["ui", "--data-dir=/data", "--ui-listen=0.0.0.0:8090", "--proxy-listen=0.0.0.0:18080"]
