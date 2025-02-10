'''Celery任务调度'''
from app.extensions import celery
from app.services.scanner import ScannerService
from app.models import ScanTask
from app.extensions import db

@celery.task(bind=True, max_retries=3)
def run_scan(self, task_id: int):
    """异步执行漏洞扫描任务"""
    try:
        task = ScanTask.query.get(task_id)
        task.status = "running"
        db.session.commit()

        # 执行Nmap扫描
        vulns = ScannerService.run_nmap_scan(task.target_url)
        ScannerService.save_vulnerabilities(task_id, vulns)

        # 更新任务状态
        task.status = "completed"
        task.finished_at = datetime.utcnow()
        db.session.commit()

    except Exception as e:
        task.status = "failed"
        db.session.commit()
        raise self.retry(exc=e)