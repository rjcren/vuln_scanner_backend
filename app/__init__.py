from flask import Flask
from app.extensions import db, make_celery, init_extensions
from app.config import BaseConfig, ProductionConfig, DevelopmentConfig, TestingConfig
from app.utils.logger import setup_logger
import os

def create_app(name: str = None):
    if name is None:
        name = os.getenv('FLASK_ENV', 'production')

    app = Flask(__name__, instance_relative_config=True)

    # 加载基础配置
    app.config.from_object(BaseConfig)
    config_map = {
        "production": ProductionConfig,
        "development": DevelopmentConfig,
        "testing": TestingConfig
    }
    if name in config_map:
        app.config.from_object(config_map[name])
        if name == "production":
            app.config.from_pyfile('instance/production.py')
    else:
        raise ValueError(f"无效配置名{name}")

    # 从环境变量加载配置（覆盖文件配置）
    app.config.from_prefixed_env()

    # 初始化扩展
    init_extensions(app)
    
    # 确保在所有配置加载完成后再初始化 Celery
    make_celery(app)

    # 注册蓝图
    register_blueprints(app)

    # 设置日志记录器
    setup_logger(app)

    # 添加全局异常处理器
    register_error_handlers(app)

    # 确保数据库表已创建
    with app.app_context():
        initialize_database(app)

    return app

def register_blueprints(app):
    from app.routes.auth import auth_bp
    from app.routes.task import tasks_bp
    from app.routes.vuls import vuls_bp
    from app.routes.feedback import feedback_bp

    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(tasks_bp, url_prefix="/api/v1/tasks")
    app.register_blueprint(vuls_bp, url_prefix="/api/v1/vuls")
    app.register_blueprint(feedback_bp, url_prefix="/api/v1/feedback")

def register_error_handlers(app):
    from app.utils.exceptions import AppException, register_error_handlers
    register_error_handlers(app)

def initialize_database(app):
    from app.utils.exceptions import InternalServerError
    from app.services.auth import AuthService
    try:
        db.create_all()
        app.logger.info("数据库表创建成功")
    except Exception as e:
        app.logger.error(f"数据库表创建失败: {str(e)}")
        raise InternalServerError(f"数据库初始化失败: {str(e)}")

    # 初始化管理员账户
    try:
        default_admin_password = AuthService.init_admin()
        if default_admin_password:
            app.logger.info("管理员账户初始化成功")
    except Exception as e:
        app.logger.error(f"管理员账户初始化失败: {str(e)}")
        raise InternalServerError(f"管理员账户初始化失败: {str(e)}")

