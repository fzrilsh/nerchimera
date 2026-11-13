FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY target-lab/go.mod ./target-lab/
COPY target-lab/ ./target-lab/
RUN cd target-lab && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/target-lab .

FROM gcr.io/distroless/static-debian12 AS runtime
COPY --from=build /out/target-lab /usr/local/bin/target-lab
USER 10002
ENV TARGET_ADDR=0.0.0.0:9190
EXPOSE 9190
ENTRYPOINT ["/usr/local/bin/target-lab"]
