'''第三方扩展模块'''
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from celery import Celery
import os
import redis
from flask_mail import Mail

mail = Mail()

# 数据库扩展
db = SQLAlchemy()
migrate = Migrate()

redis_url = os.getenv('REDIS_URI', 'redis://localhost:6379/0')
redis_client = redis.Redis.from_url(redis_url)

# Celery扩展
celery = Celery(
    __name__,
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2'),
    include=["app.tasks.scan_tasks"]
)

def init_extensions(app):
    """统一初始化所有扩展"""
    db.init_app(app)
    migrate.init_app(app, db)
    celery.conf.update(app.config)
    celery.autodiscover_tasks(['app.tasks'])  # 自动发现任务