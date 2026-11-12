FROM --platform=$BUILDPLATFORM golang:1.27.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -e; for b in tollkeeper:./cmd/tollkeeper devissuer:./cmd/devissuer notes-server:./examples/servers/notes \
      weather-server:./examples/servers/weather files-server:./examples/servers/files noop-server:./examples/servers/noop; do \
      CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" -o /out/${b%%:*} ${b#*:}; \
    done; \
    mkdir -p /out/dirs/var/log/tollkeeper /out/dirs/var/lib/tollkeeper/keys

FROM gcr.io/distroless/static-debian13:nonroot AS devissuer
COPY --from=build /out/devissuer /usr/local/bin/devissuer
USER 65532:65532
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/devissuer"]

FROM gcr.io/distroless/static-debian13:nonroot AS weather
COPY --from=build /out/weather-server /usr/local/bin/weather-server
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/weather-server"]

FROM gcr.io/distroless/static-debian13:nonroot AS files
COPY --from=build /out/files-server /usr/local/bin/files-server
USER 65532:65532
EXPOSE 8082
ENTRYPOINT ["/usr/local/bin/files-server"]

FROM gcr.io/distroless/static-debian13:nonroot AS noop
COPY --from=build /out/noop-server /usr/local/bin/noop-server
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/noop-server"]

FROM gcr.io/distroless/static-debian13:nonroot AS gateway
COPY --from=build /out/tollkeeper /usr/local/bin/tollkeeper
COPY --from=build /out/notes-server /usr/local/bin/notes-server
COPY --from=build --chown=65532:65532 /out/dirs/ /
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/tollkeeper"]
CMD ["serve", "--config", "/etc/tollkeeper/config.yaml"]
