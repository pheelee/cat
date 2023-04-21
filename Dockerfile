FROM golang:1.19-alpine as builder
ARG GOOS=linux
ARG GOARCH=amd64
ARG GOARM=7
ENV CGO_ENABLED=0
ENV GOOS=$GOOS
ENV GOARCH=$GOARCH
ENV GOARM=$GOARM
COPY ./ /go/src/Cat
RUN set -ex; \
    apk add --update --no-cache git; \
    cd /go/src/Cat; \
    mkdir -p dist; \
    go test ./...; \
    go build -o dist/Cat -ldflags "-X github.com/pheelee/Cat/internal/server.VERSION=`git rev-parse --short HEAD`" cmd/Cat/main.go

FROM alpine
RUN  addgroup -g 1000 goapp; adduser -h /app -s /sbin/nologin -G goapp -D -u 1000 goapp
COPY --from=builder --chown=goapp:goapp /go/src/Cat/dist/Cat /app/Cat
USER goapp
WORKDIR /app
CMD /app/Cat