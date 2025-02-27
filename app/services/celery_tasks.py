'''Celery任务调度'''
from app.extensions import celery
from app.services.scanner import ScannerUtils
from app.models import ScanTask
from app.extensions import db
from datetime import datetime, timezone
from app.utils.exceptions import AppException

@celery.task(bind=True, max_retries=3)
def run_scan(self, task_id: int):
    """异步执行漏洞扫描任务"""
    try:
        task = ScanTask.query.get(task_id)
        task.status = "running"
        db.session.commit()

        # 执行Nmap扫描
        vulns = ScannerUtils.run_nmap_scan(task.target_url)
        ScannerUtils.save_vulnerabilities(task_id, vulns)

        # 更新任务状态
        task.status = "completed"
        task.finished_at = datetime.now(timezone.utc)
        db.session.commit()

    except AppException as e:
        raise
    except Exception as e:
        task.status = "failed"
        db.session.commit()
        raise self.retry(exc=e)