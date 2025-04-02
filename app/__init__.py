from flask import Flask
import requests
from app.extensions import db, make_celery, init_extensions
from app.config import BaseConfig, ProductionConfig, DevelopmentConfig, TestingConfig
from app.utils.exceptions import ValidationError
from app.utils.logger import setup_logger
import os


def create_app(name: str = None) -> Flask:
    if name is None:
        name = os.getenv("FLASK_ENV", "production")

    app = Flask(__name__, instance_relative_config=True)

    # 加载基础配置
    app.config.from_object(BaseConfig)
    config_map = {
        "production": ProductionConfig,
        "development": DevelopmentConfig,
        "testing": TestingConfig,
    }
    if name in config_map:
        app.config.from_object(config_map[name])
        if name == "production":
            app.config.from_pyfile("instance/production.py")
    else:
        raise ValidationError(f"无效配置名{name}")

    # 从环境变量加载配置（覆盖文件配置）
    app.config.from_prefixed_env()

    # 初始化扩展
    init_extensions(app)
    make_celery(app)

    # 注册蓝图
    register_blueprints(app)

    # 设置日志记录器
    setup_logger(app)

    # 添加全局异常处理器
    register_error_handlers(app)

    check_services(app)

    # 确保数据库表已创建
    with app.app_context():
        initialize_database(app)

    app.app_context().push()

    return app


def register_blueprints(app):
    from app.routes.auth import auth_bp
    from app.routes.task import tasks_bp
    from app.routes.vuls import vuls_bp
    from app.routes.feedback import feedback_bp
    from app.routes.report import report_bp

    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(tasks_bp, url_prefix="/api/v1/tasks")
    app.register_blueprint(vuls_bp, url_prefix="/api/v1/vuls")
    app.register_blueprint(feedback_bp, url_prefix="/api/v1/feedback")
    app.register_blueprint(report_bp, url_prefix="/api/v1/reports")

def register_error_handlers(app):
    from app.utils.exceptions import register_error_handlers

    register_error_handlers(app)


def initialize_database(app):
    from app.services.auth import AuthService

    try:
        db.create_all()
        app.logger.info("数据库表创建成功")
    except Exception as e:
        app.logger.error(f"数据库表创建失败: {str(e)}")

    # 初始化管理员账户
    try:
        default_admin_password = AuthService.init_admin()
        if default_admin_password:
            app.logger.info("管理员账户初始化成功")
    except Exception as e:
        app.logger.error(f"管理员账户初始化失败: {str(e)}")


def check_services(app):
    try:
        if requests.get(app.config["ZAP_API_URL"], verify=False).status_code != 200:
            app.logger.warning("ZAP服务未开启或连接失败")
        else:
            app.logger.info("ZAP服务已开启")
    except Exception as e:
        app.logger.warning(f"ZAP服务未开启或连接失败")
    try:
        if requests.get(app.config["AWVS_API_URL"], verify=False).status_code != 200:
            app.logger.warning("AWVS服务未开启或连接失败")
        else:
            app.logger.info("AWVS服务已开启")
    except Exception as e:
        app.logger.warning(f"AWVS服务未开启或连接失败")
    try:
        from app.services.celery_task.celery_tasks import test
        result = test.delay()
        if not result.get(timeout=5):
            app.logger.info("Celery服务未开启或连接失败")
        else:
            app.logger.info("Celery服务已开启")
    except Exception as e:
        app.logger.warning(f"Celery服务未开启或连接失败")
    try:
        from app.extensions import redis_client

        redis_client.ping()
        app.logger.info("Redis服务已开启")
    except Exception:
        app.logger.warning(f"Redis服务未开启或连接失败")
    try:
        with app.app_context():
            from app.extensions import db
            from sqlalchemy import text
            res = db.engine.connect().execute(text("SELECT 1")).scalar()
            if res != 1:
                app.logger.warning("mysql服务未开启或连接失败")
            else:
                app.logger.info("mysql服务已开启")
    except Exception as e:
        app.logger.warning(f"mysql服务未开启或连接失败", str(e))
