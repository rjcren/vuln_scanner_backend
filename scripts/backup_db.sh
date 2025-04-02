# 数据库备份脚本
# 检查上级目录是否存在 migrations 文件夹
if [ ! -d "../migrations" ]; then
    flask db init      # 初始化迁移目录（仅首次）
fi
flask db migrate   # 生成迁移
flask db upgrade   # 应用迁移，同步数据库