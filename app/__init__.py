from flask import Flask
from app.config import Config
from app.extensions import db, migrate, celery

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # 初始化扩展
    db.init_app(app)
    migrate.init_app(app, db)
    celery.conf.update(app.config)

    # 注册蓝图
    from app.routes.auth import auth_bp
    from app.routes.tasks import tasks_bp
    from app.routes.vuls import vuls_bp
    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(tasks_bp, url_prefix="/api/v1/tasks")
    app.register_blueprint(vuls_bp, url_prefix="/api/v1/vuls")

    return app