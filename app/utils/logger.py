'''日志配置'''
import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logger(name: str) -> logging.Logger:
    """配置日志记录器"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # 文件处理器（每天轮转，保留7天）
    file_handler = RotatingFileHandler(
        os.path.join("logs", "app.log"),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=7,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)

    # 日志格式
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger