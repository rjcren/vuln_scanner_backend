#!/bin/bash
# filepath: delete_admin.sh

DB_NAME="vuln_scanner"  # 替换为你的数据库名
DB_USER="root"      # 替换为你的数据库用户名

# 创建SQL文件
cat << 'EOF' > delete_admin.sql
BEGIN;

-- 删除与用户任务关联的记录
DELETE FROM task_logs 
WHERE task_id IN (SELECT task_id FROM scan_tasks WHERE user_id = 1);

-- 删除用户任务相关的漏洞记录
DELETE FROM vulnerabilities
WHERE task_id IN (SELECT task_id FROM scan_tasks WHERE user_id = 1);

-- 删除用户反馈
DELETE FROM user_feedbacks 
WHERE user_id = 1;

-- 删除风险报告
DELETE FROM risk_reports
WHERE task_id IN (SELECT task_id FROM scan_tasks WHERE user_id = 1);

-- 删除用户的扫描任务
DELETE FROM scan_tasks 
WHERE user_id = 1;

-- 最后删除用户本身
DELETE FROM users 
WHERE user_id = 1;

COMMIT;
EOF

# 执行SQL文件
PGPASSWORD="${DB_PASSWORD}" psql -U "${DB_USER}" -d "${DB_NAME}" -f delete_admin.sql

# 清理临时SQL文件
rm delete_admin.sql

echo "ID为1的管理员用户及其相关数据已被删除"