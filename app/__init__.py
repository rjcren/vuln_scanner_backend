from flask import Flask
from app.extensions import db, migrate, celery
from app.config import *
from app.utils.exceptions import InternalServerError, register_error_handlers
from app.utils.logger import setup_logger
import os

def create_app(name:str = None):
    if name is None:
        name = os.getenv('FLASK_ENV', 'production')

    app = Flask(__name__, instance_relative_config=True)

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
    register_error_handlers(app)

    # 注册蓝图
    from app.routes.auth import auth_bp
    from app.routes.tasks import tasks_bp
    from app.routes.vuls import vuls_bp
    from app.routes.admin import admin_bp
    from app.routes.feedback import feedback_bp

    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(tasks_bp, url_prefix="/api/v1/tasks")
    app.register_blueprint(vuls_bp, url_prefix="/api/v1/vuls")
    app.register_blueprint(admin_bp, url_prefix="/api/v1/admin")
    app.register_blueprint(feedback_bp, url_prefix="/api/v1/feedback")

    # 配置根日志记录器（确保所有模块继承）
    app.logger.propagate = True

    return app