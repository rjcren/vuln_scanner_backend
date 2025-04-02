# 启动mysql
service mysql start

# 启动celery
celery -A celery_worker.celery worker --loglevel=info