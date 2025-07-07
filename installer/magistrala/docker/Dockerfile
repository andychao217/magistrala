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

WORKDIR /go/src/github.com/andychao217/magistrala
COPY . .

RUN echo http://mirrors.aliyun.com/alpine/v3.19/main/ > /etc/apk/repositories && \
    echo http://mirrors.aliyun.com/alpine/v3.19/community/ >> /etc/apk/repositories && \
    apk update && apk upgrade && \
    apk add --no-cache make

# 安装 UPX（如果可用），否则手动下载并安装
RUN if apk add --no-cache upx; then \
        echo "UPX 已通过 apk 安装"; \
    else \
        echo "通过 apk 安装 UPX 失败，尝试手动安装"; \
        wget https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-amd64_linux.tar.xz && \
        tar -xf upx-4.2.4-amd64_linux.tar.xz && \
        mv upx-4.2.4-amd64_linux/upx /usr/local/bin/ && \
        rm -rf upx-4.2.4-amd64_linux upx-4.2.4-amd64_linux.tar.xz; \
    fi

RUN make GOOS=$TARGETOS GOARCH=$TARGETARCH $SVC \
    && mv build/$SVC /exe \
    && upx --best /exe  # 使用 UPX 压缩可执行文件

FROM scratch
# Certificates are needed so that mailing util can work.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /exe /
ENTRYPOINT ["/exe"]
