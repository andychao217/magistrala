# Builder
FROM erlang:25.3.2.8-alpine AS builder

# 安装依赖和工具
RUN apk add --update git build-base bsd-compat-headers openssl-dev snappy-dev curl

# 克隆 VerneMQ 源码
RUN git clone -b 1.13.0 https://github.com/vernemq/vernemq /vernemq

# 初始化子模块
RUN cd /vernemq && git submodule update --init --recursive

# 确保所有子模块都已正确克隆和初始化
RUN cd /vernemq && for submodule in $(git submodule--helper list | awk '{print \$4}'); do git submodule update --init --recursive $submodule; done

# 确保 _build 目录存在
RUN mkdir -p /vernemq/_build/default/lib/eleveldb/c_src

# 手动克隆并构建 leveldb
RUN cd /vernemq/_build/default/lib/eleveldb/c_src && \
    git clone --depth=1 --branch="2.0.38" https://github.com/basho/leveldb && \
    cd leveldb && git submodule update --init --recursive && \
    make

# 确认 leveldb 及其子模块已被克隆
RUN [ -d /vernemq/_build/default/lib/eleveldb/c_src/leveldb ] && \
    [ -d /vernemq/_build/default/lib/eleveldb/c_src/leveldb/leveldb_ee ]

# 用构建脚本生成 VerneMQ
RUN cd /vernemq && make -j 16 rel

# Executor
FROM alpine:3.19

COPY --from=builder /vernemq/_build/default/rel /

RUN apk --no-cache --update --available upgrade && \
    apk add --no-cache ncurses-libs openssl libstdc++ jq curl bash snappy-dev && \
    addgroup --gid 10000 vernemq && \
    adduser --uid 10000 -H -D -G vernemq -h /vernemq vernemq && \
    install -d -o vernemq -g vernemq /vernemq

# Defaults
ENV DOCKER_VERNEMQ_KUBERNETES_LABEL_SELECTOR="app=vernemq" \
    DOCKER_VERNEMQ_LOG__CONSOLE=console \
    PATH="/vernemq/bin:$PATH" \
    VERNEMQ_VERSION="1.13.0"

WORKDIR /vernemq

COPY --chown=10000:10000 bin/vernemq.sh /usr/sbin/start_vernemq
COPY --chown=10000:10000 files/vm.args /vernemq/etc/vm.args

RUN chown -R 10000:10000 /vernemq && \
    ln -s /vernemq/etc /etc/vernemq && \
    ln -s /vernemq/data /var/lib/vernemq && \
    ln -s /vernemq/log /var/log/vernemq

# Ports
# 1883  MQTT
# 8883  MQTT/SSL
# 8080  MQTT WebSockets
# 44053 VerneMQ Message Distribution
# 4369  EPMD - Erlang Port Mapper Daemon
# 8888  Health, API, Prometheus Metrics
# 9100 9101 9102 9103 9104 9105 9106 9107 9108 9109 Specific Distributed Erlang Port Range

EXPOSE 1883 8883 8080 44053 4369 8888 \
       9100 9101 9102 9103 9104 9105 9106 9107 9108 9109

VOLUME ["/vernemq/log", "/vernemq/data", "/vernemq/etc"]

HEALTHCHECK CMD vernemq ping | grep -q pong

USER vernemq
CMD ["start_vernemq"]
