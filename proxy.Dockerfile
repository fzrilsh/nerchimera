# Build the C++ engine and the Go proxy, then run on a slim runtime.
FROM golang:1.25-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ make ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# Engine first (its archive is cached unless engine sources change).
COPY engine/ ./engine/
COPY Makefile ./
RUN make engine

# Go module cache.
COPY go.work ./
COPY proxy/go.mod proxy/go.sum ./proxy/
COPY target-lab/go.mod ./target-lab/
RUN cd proxy && go mod download

COPY proxy/ ./proxy/
RUN cd proxy && CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/netchimera .

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 10001 --no-create-home chimera
COPY --from=build /out/netchimera /usr/local/bin/netchimera
USER chimera
ENV PROXY_ADDR=0.0.0.0:8080 API_ADDR=0.0.0.0:8081
EXPOSE 8080 8081
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8081/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/netchimera"]
