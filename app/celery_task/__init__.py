from celery import Celery

# 创建一个独立的 Celery 实例用于任务发现
default_app = Celery('app')

# 设置基本配置
default_app.conf.update(
    broker_connection_retry_on_startup=True,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json'
)
