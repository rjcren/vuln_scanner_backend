from flask import Flask
from app.extensions import db, migrate, celery
from app.config import DevelopmentConfig, TestingConfig
from instance.production import ProductionConfig
from app.utils.exceptions import register_error_handlers
from app.utils.logger import setup_logger

def create_app(name):
    app = Flask(__name__)
    if name == "development":
        app.config.from_object(DevelopmentConfig)
        if name == "production":
            app.config.from_object(ProductionConfig)
    elif name == "testing":
        app.config.from_object(TestingConfig)

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