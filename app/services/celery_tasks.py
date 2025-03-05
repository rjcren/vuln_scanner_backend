'''Celery任务调度'''
from app.extensions import celery
from app.models.vulnerability import Vulnerability
from app.models import ScanTask
from app.extensions import db
from datetime import datetime, timezone
from app.services.vul import VulService
from app.utils.exceptions import AppException, InternalServerError, BadRequest
from app.utils.scanner import ScannerUtils

class CeleryTasks:
    @staticmethod
    @celery.task(bind=True, max_retries=3)
    def run_scan(task_id: int):
        """异步执行漏洞扫描任务"""
        task = ScanTask.query.get(task_id)
        if not task:
            BadRequest(f"扫描任务 {task_id} 不存在")
        try:
            # 执行核心扫描
            scan_results = []
            scan_results += ScannerUtils.run_nmap(task.target_url)
            scan_results += ScannerUtils.run_zap(task.target_url)

            # 保存结果
            VulService._save_results(task.id, scan_results)

            task.status = "completed"
        except Exception as e:
            task.status = "failed"
            raise InternalServerError(f"扫描任务 {task_id} 执行异常: {str(e)}")
        finally:
            db.session.commit()

