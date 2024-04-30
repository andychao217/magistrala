# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0


FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder

# 设置GOPROXY环境变量
ENV GOPROXY=https://goproxy.cn,https://goproxy.io,https://mirrors.aliyun.com/goproxy/,https://proxy.golang.org,direct
#5.更新Alpine的软件源为阿里云，因为从默认官源拉取实在太慢了

ARG TARGETOS
ARG TARGETARCH
ARG SVC
ARG VERSION
ARG COMMIT
ARG TIME

WORKDIR /go/src/github.com/absmach/magistrala
COPY . .

RUN echo http://mirrors.aliyun.com/alpine/v3.19/main/ > /etc/apk/repositories && \
    echo http://mirrors.aliyun.com/alpine/v3.19/community/ >> /etc/apk/repositories

RUN apk update \
    && apk upgrade \
    && apk add make\
    && make GOOS=$TARGETOS GOARCH=$TARGETARCH $SVC \
    && mv build/$SVC /exe

FROM scratch
# Certificates are needed so that mailing util can work.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /exe /
ENTRYPOINT ["/exe"]
