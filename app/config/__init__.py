from .development import DevelopmentConfig
from .production import ProductionConfig
from .testing import TestingConfig

class BaseConfig:
    # 公共配置项（如密钥、数据库URI）
    SECRET_KEY = "your-secret-key"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    