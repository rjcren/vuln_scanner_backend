class Config:
    HOSTNAME = "0.0.0.0"
    PORT = 5000
    # 数据库配置
    DATABASE_HOSTNAME = "127.0.0.1"
    DATABASE_PORT = 3306
    USERNAME = "root"
    PASSWORD = "root"
    DATABASE = "vuln_scanner"
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{USERNAME}:{PASSWORD}@{DATABASE_HOSTNAME}:{DATABASE_PORT}/{DATABASE}?charset=utf8'

    # 公共配置项
    SECRET_KEY = "test-secret-key"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_EXPIRATION_HOURS = 1
    CELERY_BROKER_URL = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND = "redis://localhost:6379/1"
    