from flask import Flask
from flask_migrate import Migrate  # 数据库迁移
import app.config.development as development
from app.extensions import db
import app.models.*
from app.routes.user import db as user_db
from app.routes.message import bp as message_bp

app = Flask(__name__)
# 绑定配置
app.config.from_object(development)

db.init_app(app)

Migrate(app, db)
'''
    ORM模型映射成表的三步
    1.flask db init:这步只需要执行一次
    2.flask db migrate:识别ORM模型的攻变，生成迁移脚本
    3.flask db upgrade:运行迁移脚本，同步到数据库
'''

if __name__ == '__main__':
    app.run()
