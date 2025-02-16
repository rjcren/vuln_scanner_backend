# 数据库备份脚本
flask db init      # 初始化迁移目录（仅首次）
flask db migrate   # 生成迁移
flask db upgrade   # 应用迁移，同步数据库