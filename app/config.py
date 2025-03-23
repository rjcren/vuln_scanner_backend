import os
class BaseConfig:
    # 公共配置项
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-key")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PROPAGATE_EXCEPTIONS = True

    REDIS_URL = os.getenv("REDIS_URI", "redis://localhost:6379/0")

    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', 1))
    SECRET_KEY = os.getenv('SECRET_KEY', "test_secret_key")

    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 465))
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'True') == 'True'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')

    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI", "mysql+pymysql://root:root@127.0.0.1:3306/vuln_scanner?charset=utf8")

    # Celery配置
    broker_url = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')  # 修改了环境变量名以匹配新的格式
    result_backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')  # 同上
    task_serializer = 'json'
    result_serializer = 'json'
    accept_content = ['json']
    timezone = 'Asia/Shanghai'
    enable_utc = True
    worker_hijack_root_logger = False
    task_default_queue = 'default'
    task_acks_late = True
    task_reject_on_worker_lost = True
    task_track_started = True
    broker_connection_retry_on_startup = True
    result_extended = True
    imports = ['app.celery_task.celery_tasks']
    worker_concurrency = 3

class DevelopmentConfig(BaseConfig):
    DEBUG = True

class ProductionConfig(BaseConfig):
    pass

class TestingConfig(BaseConfig):
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    TESTING = True
