'''扫描任务执行逻辑'''
from datetime import datetime
from celery import shared_task
from app.extensions import db, celery
from app.models import ScanTask, Vulnerability, TaskLog
from app.services.scanner import ScannerService
from app.utils.logger import setup_logger

logger = setup_logger(__name__)

@celery.task(name="run_scan_task", bind=True, max_retries=3, acks_late=True)
def run_scan_task(self, task_id: int):
    """执行漏洞扫描核心任务（支持重试）"""
    try:
        task = db.session.get(ScanTask, task_id)
        if not task:
            logger.error(f"任务 {task_id} 不存在")
            return

        # 更新任务状态为运行中
        task.status = "running"
        task.started_at = datetime.utcnow()
        db.session.commit()

        # 记录日志
        TaskLog.log(task_id, "开始执行扫描...")

        # 调用扫描引擎
        if task.scan_type == "nmap":
            vulnerabilities = ScannerService.run_nmap_scan(task.target_url)
        elif task.scan_type == "zap":
            vulnerabilities = ScannerService.run_zap_scan(task.target_url)
        else:
            raise ValueError(f"不支持的扫描类型: {task.scan_type}")

        # 保存漏洞结果
        ScannerService.save_vulnerabilities(task_id, vulnerabilities)

        # 标记任务完成
        task.status = "completed"
        task.finished_at = datetime.utcnow()
        db.session.commit()
        TaskLog.log(task_id, "扫描成功完成")

    except Exception as e:
        # 失败时重试
        db.session.rollback()
        task.status = "failed"
        db.session.commit()
        TaskLog.log(task_id, f"扫描失败: {str(e)}")
        raise self.retry(exc=e, countdown=60)