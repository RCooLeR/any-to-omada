# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
# check=error=true

# Build from the standalone repository root.
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build

ARG TARGETOS
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /src

COPY --link go.mod go.sum ./
RUN go mod download && go mod verify

COPY --link cmd ./cmd
COPY --link internal ./internal
RUN --network=none \
    --mount=type=cache,id=any-to-omada-go-build,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -mod=readonly -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/any-to-omada ./cmd/any-to-omada
RUN mkdir -p /out/data && chmod 0700 /out/data

# All outgoing protocols are pinned local TCP; no transcoder or shell is required.
FROM scratch AS runtime
COPY --link --from=build --chmod=0555 /out/any-to-omada /any-to-omada
COPY --link --from=build --chown=10001:10001 /out/data /data
COPY --link LICENSE NOTICE THIRD_PARTY_NOTICES /licenses/
COPY --link docs/legal.md /licenses/docs/legal.md
COPY --link --from=build /src/internal/spakeee/NOTICE /src/internal/spakeee/DEPENDENCY_NOTICES /licenses/internal/spakeee/

LABEL org.opencontainers.image.title="Any to Omada" \
    org.opencontainers.image.description="Experimental camera interoperability workaround with authenticated Omada callbacks" \
    org.opencontainers.image.source="https://github.com/RCooLeR/any-to-omada" \
    org.opencontainers.image.licenses="MIT"
USER 10001:10001
EXPOSE 18443 18444 18445 18446 18447 18448 18554 18555 18556 18557 18558 18559
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/any-to-omada", "healthcheck", "--config", "/config/config.json"]
ENTRYPOINT ["/any-to-omada"]
CMD ["serve", "--config", "/config/config.json"]
