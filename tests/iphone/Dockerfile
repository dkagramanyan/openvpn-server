FROM golang:1.26.11-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /iphonetest .

FROM alpine:3.24.4
RUN apk add --no-cache openssl && mkdir /state && chown 65532:65532 /state
COPY --from=build /iphonetest /usr/local/bin/iphonetest
USER 65532:65532
ENTRYPOINT ["iphonetest"]
