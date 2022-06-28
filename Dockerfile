ARG GO_VERSION=1.18
ARG ALPINE_VERSION=3.15

FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

RUN apk update && \
    apk add --no-cache \
    ca-certificates \
    git \
    tzdata

WORKDIR /app

ADD . .

RUN go mod download

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build --trimpath --ldflags "-w -s" \
    -o /app/trojan-go \
    cmd/trojan/main.go

FROM alpine:${ALPINE_VERSION}

ENV TZ=Asia/Shanghai
COPY --from=builder /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

COPY --from=builder /app/trojan-go /usr/local/bin/trojan-go
COPY --from=builder /app/server.json /etc/trojan-go/config.json

CMD ["/usr/local/bin/trojan-go", "-c", "/etc/trojan-go/config.json"]