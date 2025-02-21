import os
class BaseConfig:
    DEBUG = False
    HOSTNAME = "0.0.0.0"
    PORT = 5000
    # 公共配置项
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PROPAGATE_EXCEPTIONS = True
    
    JWT_EXPIRATION_HOURS = 1
    CELERY_BROKER_URL = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND = "redis://localhost:6379/1"

class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv('DEV_DB_URI', 'mysql+pymysql://root:root@127.0.0.1:3306/vuln_scanner?charset=utf8')

class ProductionConfig(BaseConfig):
    SQLALCHEMY_DATABASE_URI = os.getenv('PROD_DB_URI')

class TestingConfig(BaseConfig):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    TESTING = True
