FROM golang:1.26.10-alpine AS build
WORKDIR /src
COPY relay/go.mod relay/go.sum ./
RUN go mod download
COPY relay/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /apple-relay .

FROM alpine:3.24.2
RUN apk add --no-cache ca-certificates
ENV GODEBUG=http2xconnect=1
COPY --from=build /apple-relay /usr/local/bin/apple-relay
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8446/healthz || exit 1
ENTRYPOINT ["apple-relay"]
