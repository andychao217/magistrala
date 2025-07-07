#!/bin/bash

# 等待 PostgreSQL 服务完全启动
echo "等待 PostgreSQL 服务启动..."
sleep 10

# 检查必要的环境变量是否设置
if [ -z "$POSTGRES_HOST" ]; then
    echo "错误: 未设置 POSTGRES_HOST 环境变量"
    exit 1
fi

if [ -z "$POSTGRES_USER" ]; then
    echo "错误: 未设置 POSTGRES_USER 环境变量"
    exit 1
fi

if [ -z "$POSTGRES_DB" ]; then
    echo "错误: 未设置 POSTGRES_DB 环境变量"
    exit 1
fi

if [ -z "$POSTGRES_PASSWORD" ]; then
    echo "错误: 未设置 POSTGRES_PASSWORD 环境变量"
    exit 1
fi

# 使用 psql 命令连接到 PostgreSQL 并执行 SQL 命令
echo "尝试连接到数据库: $POSTGRES_HOST:$POSTGRES_DB"
PGPASSWORD=$POSTGRES_PASSWORD psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
DO \$\$
BEGIN
   -- 检查表是否存在
   IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'clients') THEN
       -- 更新 metadata 字段
       UPDATE clients
       SET metadata = jsonb_set(metadata::jsonb, '{is_online}', '\"0\"', true)
       WHERE metadata::jsonb->'is_online' ? '1';
       RAISE NOTICE '已重置设备在线状态';
   ELSE
       RAISE NOTICE 'clients 表不存在，跳过重置在线状态';
   END IF;
END
\$\$;
"

echo "脚本执行完成"