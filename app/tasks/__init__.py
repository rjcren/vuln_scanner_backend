'''Celery实例初始化'''
from app.extensions import celery
from .scan_tasks import run_scan_task
from .periodic_tasks import sync_threat_intel_task
from .plugin_tasks import run_plugin_task

# 显式导入任务确保Celery发现
__all__ = ["celery"]