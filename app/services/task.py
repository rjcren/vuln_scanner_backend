'''任务管理'''
from app.models import ScanTask, TaskLog
from app.extensions import db
from app.tasks.scan_tasks import run_scan_task
from datetime import datetime, timezone

class TaskService:
    @staticmethod
    def create_task(user_id: int, target_url: str, scan_type: str) -> ScanTask:
        # 创建任务记录
        task = ScanTask(
            user_id=user_id,
            target_url=target_url,
            scan_type=scan_type
        )
        db.session.add(task)
        db.session.commit()

        # 记录日志
        TaskService._log_task(task.task_id, "任务已创建")

        # 异步启动扫描
        run_scan_task.delay(task.task_id)
        return task

    @staticmethod
    def get_tasks(role: str, user_id: int, page: int, size: int):
        query = None
        if role == 'admin': query = ScanTask.query.order_by(ScanTask.created_at.desc())
        else: query = ScanTask.query.filter_by(user_id=user_id).order_by(ScanTask.created_at.desc())
        return query.paginate(page=page, per_page=size, error_out=False)

    @staticmethod
    def _log_task(task_id: int, message: str):
        log = TaskLog(task_id=task_id, log_message=message)
        db.session.add(log)
        db.session.commit()