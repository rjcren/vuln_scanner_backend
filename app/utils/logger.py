'''日志配置'''
import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logger(app):
    """统一日志配置"""
    log_path = os.path.join(app.root_path, 'logs/app.log')

    # 确保日志目录存在
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')

    file_handler = RotatingFileHandler(
        log_path, maxBytes=1024 * 1024 * 10, backupCount=10, encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG if app.debug else logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    app.logger.propagate = True  # 确保下游也能接收到日志
