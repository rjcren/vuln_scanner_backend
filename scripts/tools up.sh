# 启动mysql
service mysql start

# 启动AWVS  https://localhost:3443
sudo systemctl start acunetix

# 启动celery
celery -A celery_worker.celery worker --loglevel=info