FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o aegis-oracle ./cmd/aegis-oracle && \
    go build -ldflags="-s -w" -o aegis-oracle-cli ./cmd/aegis-oracle-cli

# ── Runtime image ──────────────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S oracle && adduser -S oracle -G oracle

WORKDIR /app

COPY --from=builder /build/aegis-oracle     ./aegis-oracle
COPY --from=builder /build/aegis-oracle-cli ./aegis-oracle-cli
COPY knowledgebase/                          ./knowledgebase/
COPY cmd/aegis-oracle/config.yaml           ./config.yaml

USER oracle

EXPOSE 8742

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8742/health || exit 1

ENTRYPOINT ["./aegis-oracle"]
CMD ["-config", "config.yaml"]
