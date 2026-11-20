# syntax=docker/dockerfile:1
# Base images are pinned by digest; Dependabot keeps them current.

FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/certly ./cmd/certly \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
LABEL org.opencontainers.image.title="Certly" \
      org.opencontainers.image.description="A small private CA for homelab mTLS" \
      org.opencontainers.image.source="https://github.com/quantumryuu/Certly" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/certly /certly
# nonroot = uid/gid 65532; the data dir must be owned by it and private.
COPY --from=build --chown=65532:65532 --chmod=0700 /out/data /data
ENV CERTLY_DATA_DIR=/data \
    CERTLY_LISTEN=:8080
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/certly", "healthcheck"]
ENTRYPOINT ["/certly"]
CMD ["serve"]
