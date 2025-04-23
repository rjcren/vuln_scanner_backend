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

    # 扫描工具配置
    AWVS_API_URL = os.getenv("AWVS_API_URL", "https://127.0.0.1:3443").strip("/")
    AWVS_API_KEY = os.getenv("AWVS_API_KEY", "none")
    ZAP_API_URL = os.getenv("ZAP_API_URL", "https://127.0.0.1:8080").strip("/")
    ZAP_API_KEY = os.getenv("ZAP_API_KEY", "none")
    XRAY_OUTPUT_PATH = os.getenv("XRAY_OUTPUT_PATH", "/tmp/xray_output.json")
    XRAY_PATH = os.getenv("XRAY_PATH", "/usr/local/bin/xray")

    # Celery配置
    broker_url = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    result_backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')

    API_key = os.getenv("API_KEY", "default_api_key")

class DevelopmentConfig(BaseConfig):
    DEBUG = True

class ProductionConfig(BaseConfig):
    pass

class TestingConfig(BaseConfig):
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    TESTING = True
