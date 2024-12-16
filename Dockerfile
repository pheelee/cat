FROM node:lts-alpine AS frontend
ARG BUILD_VERSION=dev
WORKDIR /app
COPY ./frontend /app
RUN echo VITE_APP_VERSION=$BUILD_VERSION > .env; \
    corepack enable; \
    yarn install; \
    yarn build

FROM golang:1.23-alpine AS builder
ARG GOOS=linux
ARG GOARCH=amd64
ARG GOARM=7
ARG BUILD_VERSION=dev
ENV CGO_ENABLED=0
ENV GOOS=$GOOS
ENV GOARCH=$GOARCH
ENV GOARM=$GOARM
COPY ./ /go/src/Cat
COPY --from=frontend /app/dist /go/src/Cat/internal/web/dist
RUN set -ex; \
    cd /go/src/Cat; \
    mkdir -p dist; \
    go test ./...; \
    go build -o dist/Cat -ldflags "-X main.VERSION=$BUILD_VERSION" cmd/Cat/main.go

FROM alpine
ENV PORT=8090
RUN  addgroup -g 1000 goapp; adduser -h /app -s /sbin/nologin -G goapp -D -u 1000 goapp
COPY --from=builder --chown=goapp:goapp /go/src/Cat/dist/Cat /app/Cat
USER goapp
WORKDIR /app
HEALTHCHECK --interval=30s --timeout=1s --retries=1 CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/health || exit 1
CMD ["/app/Cat"]
