'''第三方扩展模块'''
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from celery import Celery

# 数据库扩展
db = SQLAlchemy()
migrate = Migrate()

# Celery扩展
celery = Celery(
    __name__,
    broker="redis://redis:6379/0",
    backend="redis://redis:6379/1",
    include=["app.tasks.scan_tasks"]
)

# JWT配置（通过Flask app.config加载）
jwt_secret = None

def init_extensions(app):
    """统一初始化所有扩展"""
    db.init_app(app)
    migrate.init_app(app, db)
    celery.conf.update(app.config)
    global jwt_secret
    jwt_secret = app.config["SECRET_KEY"]
    celery.autodiscover_tasks(['app.tasks'])  # 自动发现任务