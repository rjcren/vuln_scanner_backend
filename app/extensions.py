from flask_sqlalchemy import SQLAlchemy
from celery import Celery
from flask_migrate import Migrate
from flask import Flask
from flask_cors import CORS
import os
from flask_mail import Mail
import redis

mail = Mail()
db = SQLAlchemy()
migrate = Migrate()
celery = Celery()

redis_url = os.getenv("REDIS_URI", "redis://localhost:6379/0")
redis_client = redis.Redis.from_url(redis_url)

def make_celery(app):
    """初始化 Celery"""
    celery.conf.update(
        broker_connection_retry_on_startup=True,
        worker_hijack_root_logger = False,
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone = 'Asia/Shanghai',
        enable_utc = True,
        task_default_queue = 'default',
        task_acks_late = True,
        task_reject_on_worker_lost = True,
        task_track_started = True,
        result_extended = True,
        imports = ['app.services.celery_task.celery_tasks'],
        worker_concurrency = 3
    )

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask

    # 在设置完所有配置后再自动发现任务
    celery.autodiscover_tasks(['app.celery_task'], force=True)
    return celery

def init_extensions(app: Flask):
    """统一初始化所有扩展"""
    # 初始化数据库、邮件等
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    # 初始化 CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": ["https://192.168.125.1:443", "https://192.168.125.1:444", "http://192.168.125.1:80"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "expose_headers": ["Content-Range", "X-Total-Count"],
            "supports_credentials": True,
        }
    })