FROM golang:1.21-alpine AS builder
ARG GOOS=linux
ARG GOARCH=amd64
ARG GOARM=7
ARG BUILD_VERSION=dev
ENV CGO_ENABLED=0
ENV GOOS=$GOOS
ENV GOARCH=$GOARCH
ENV GOARM=$GOARM
COPY ./ /go/src/Cat
RUN set -ex; \
    cd /go/src/Cat; \
    mkdir -p dist; \
    go test ./...; \
    go build -o dist/Cat -ldflags "-X github.com/pheelee/Cat/internal/server.VERSION=$BUILD_VERSION" cmd/Cat/main.go

FROM alpine
RUN  addgroup -g 1000 goapp; adduser -h /app -s /sbin/nologin -G goapp -D -u 1000 goapp
COPY --from=builder --chown=goapp:goapp /go/src/Cat/dist/Cat /app/Cat
USER goapp
WORKDIR /app
CMD ["/app/Cat"]
