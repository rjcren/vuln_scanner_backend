from datetime import datetime
import logging
from app.extensions import db, celery
from app.models.task_log import TaskLog
from app.models import ScanTask
from app.services.scanner.AWVS import AWVS
from app.utils.exceptions import AppException

logger = logging.getLogger(__name__)

@celery.task(bind=True, max_retries=200)
def save_awvs_vuls(self, task_id, scan_id):
    from app import create_app
    app = create_app()
    with app.app_context():
        try:
            res = AWVS.save_vuls(task_id, scan_id)
            if not res:
                raise self.retry(countdown=30)
            return True
        except AppException:
            raise 
        except Exception as e:
            raise
        
@celery.task(bind=True, max_retries=200)
def save_xray_vuls(self, task_id):
    try:
        TaskLog.add_log(task_id, "INFO", "Xray扫描结束")
        return True
    except Exception as e:
        raise

@celery.task(bind=True,max_retries=5)
def update_task_status(self, group_results, task_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        task = None
        try:
            task = ScanTask.query.filter_by(task_id=task_id).first()
            if task is None:
                TaskLog.add_log(task_id, "ERROR", "任务不存在")
                raise ValueError("任务不存在")
            
            if task.status == "running":
                # 判断任务是否成功
                awvs_success = group_results[0]
                xray_success = group_results[1]
                # 更新任务状态
                if awvs_success: TaskLog.add_log(task_id, "INFO", "AWVS扫描成功")
                else: TaskLog.add_log(task_id, "ERROR", "AWVS扫描失败")
                if xray_success: TaskLog.add_log(task_id, "INFO", "Xray扫描成功")
                else: TaskLog.add_log(task_id, "ERROR", "Xray扫描失败")

                task.finished_at = datetime.now()
                task.update_status("completed")
                db.session.commit()
                TaskLog.add_log(task_id, "INFO", "扫描结束")
        except Exception as e:
            db.session.rollback()
            if task:
                task.finished_at = datetime.now()
                task.update_status("failed")
                db.session.commit()
            TaskLog.add_log(task_id, "ERROR", f"更新任务状态失败: {str(e)}")
            raise