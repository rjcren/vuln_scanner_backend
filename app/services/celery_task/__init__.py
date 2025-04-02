# from celery import Celery

# # 创建一个独立的 Celery 实例用于任务发现
# default_app = Celery('app')

# # 设置基本配置
# default_app.conf.update(
#     broker_connection_retry_on_startup=True,
#     worker_hijack_root_logger = False,
#     task_serializer='json',
#     accept_content=['json'],
#     result_serializer='json',
#     timezone = 'Asia/Shanghai',
#     enable_utc = True,
#     task_default_queue = 'default',
#     task_acks_late = True,
#     task_reject_on_worker_lost = True,
#     task_track_started = True,
#     result_extended = True,
#     imports = ['app.services.celery_task.celery_tasks'],
#     worker_concurrency = 3
# )
