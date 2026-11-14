FROM --platform=$BUILDPLATFORM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
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

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS devissuer
COPY --from=build /out/devissuer /usr/local/bin/devissuer
USER 65532:65532
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/devissuer"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS weather
COPY --from=build /out/weather-server /usr/local/bin/weather-server
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/weather-server"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS files
COPY --from=build /out/files-server /usr/local/bin/files-server
USER 65532:65532
EXPOSE 8082
ENTRYPOINT ["/usr/local/bin/files-server"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS noop
COPY --from=build /out/noop-server /usr/local/bin/noop-server
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/noop-server"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS gateway
COPY --from=build /out/tollkeeper /usr/local/bin/tollkeeper
COPY --from=build /out/notes-server /usr/local/bin/notes-server
COPY --from=build --chown=65532:65532 /out/dirs/ /
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/tollkeeper"]
CMD ["serve", "--config", "/etc/tollkeeper/config.yaml"]
