class BaseConfig:
    # 公共配置项
    SECRET_KEY = "your-secret-key-here"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_EXPIRATION_HOURS = 1
    CELERY_BROKER_URL = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND = "redis://localhost:6379/1"
    # 数据库
    HOSTNAME = "127.0.0.1"
    POST = 3306
    USERNAME = "root"
    PASSWORD = "root"
    DATABASE = "test"
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{USERNAME}:{PASSWORD}@{HOSTNAME}:{POST}/{DATABASE}?charset=utf8'

    JWT_EXPIRATION_HOURS = 1
    CELERY_BROKER_URL = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND = "redis://localhost:6379/1"