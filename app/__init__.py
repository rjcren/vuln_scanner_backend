from flask import Flask
from flask_cors import CORS
from app.extensions import db, migrate, celery, mail
from app.config import *
from app.utils.exceptions import InternalServerError, register_error_handlers
from app.utils.logger import setup_logger
import os

def create_app(name:str = None):
    if name is None:
        name = os.getenv('FLASK_ENV', 'production')

    from dotenv import load_dotenv
    load_dotenv(verbose=True)

    app = Flask(__name__, instance_relative_config=True)

    # 手动设置
    app.config['JWT_EXPIRATION_HOURS'] = int(os.getenv('JWT_EXPIRATION_HOURS', default=1))
    app.config["SECRET_KEY"] = os.getenv('SECRET_KEY', "test_secret_key")
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
    app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'True') == 'True'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    # 忽略ssl证书验证
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"connect_args": {"ssl": {"ssl_cert_reqs": "CERT_NONE"}}}

    mail.init_app(app)
    CORS(app, supports_credentials=True, origins=["*"])

    app.config.from_object(BaseConfig)
    if name == "production":
        app.config.from_object(ProductionConfig)
        # 加载instance目录的生产配置
        app.config.from_pyfile('instance/production.py')
    elif name == "development":
        app.config.from_object(DevelopmentConfig)
    elif name == "testing":
        app.config.from_object(TestingConfig)
    else: raise ValueError(f"无效配置名{name}")

    # 3. 加载环境变量（覆盖文件配置）
    app.config.from_prefixed_env()

    # 初始化扩展
    setup_logger(app)
    db.init_app(app)
    migrate.init_app(app, db)
    celery.conf.update(app.config)

    # 注册蓝图
    from app.routes.auth import auth_bp
    from app.routes.task import tasks_bp
    from app.routes.vuls import vuls_bp
    from app.routes.feedback import feedback_bp

    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(tasks_bp, url_prefix="/api/v1/tasks")
    app.register_blueprint(vuls_bp, url_prefix="/api/v1/vuls")
    app.register_blueprint(feedback_bp, url_prefix="/api/v1/feedback")

    # 配置根日志记录器（确保所有模块继承）
    app.logger.propagate = True

    # 添加全局异常处理器
    from app.utils.exceptions import AppException, register_error_handlers
    register_error_handlers(app)

    return app