#!/bin/bash

# 等待 PostgreSQL 服务完全启动
sleep 10

# 使用 psql 命令连接到 PostgreSQL 并执行 SQL 命令
PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB -c "
DO \$\$
BEGIN
   -- 检查表是否存在
   IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'clients') THEN
       -- 更新 metadata 字段
       UPDATE clients
       SET metadata = jsonb_set(metadata::jsonb, '{is_online}', '\"0\"', true)
       WHERE metadata::jsonb->'is_online' ? '1';
   END IF;
END
\$\$;
"
