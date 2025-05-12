from datetime import datetime
import logging
from app.extensions import db, celery
from app.models.task_log import TaskLog
from app.models import ScanTask
from app.services.scanner.AWVS import AWVS
from app.services.scanner.ZAP import ZAP
from app.utils.exceptions import AppException, ValidationError

logger = logging.getLogger(__name__)

@celery.task(bind=True, max_retries=200)
def save_awvs_vuls(self, task_id, scan_id):
    from flask import current_app as app
    with app.app_context():
        try:
            res = AWVS().save_vuls(task_id, scan_id)
            if not res:
                raise self.retry(countdown=30)
            return True
        except AppException:
            raise 
        except Exception as e:
            print(f"awvs celery: {e}")
            raise
        
@celery.task(bind=True, max_retries=200)
def save_zap_vuls(self, task_id, scan_id, url):
    from flask import current_app as app
    with app.app_context():
        try:
            res = ZAP().save_vuls(task_id, scan_id, url)
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
    from flask import current_app as app
    with app.app_context():
        task = None
        try:
            task = ScanTask.query.filter_by(task_id=task_id).first()
            if task is None:
                TaskLog.add_log(task_id, "ERROR", "任务不存在")
                raise ValidationError("任务不存在")
            if task.status == "running" and group_results:
                # 判断任务是否成功
                print(f"group_results:{group_results}")
                # 更新任务状态
                if group_results[0]: TaskLog.add_log(task_id, "INFO", "AWVS扫描成功")
                else: TaskLog.add_log(task_id, "ERROR", "AWVS扫描失败")
                if len(group_results)>1 and group_results[1]: TaskLog.add_log(task_id, "INFO", "ZAP扫描成功")
                else: TaskLog.add_log(task_id, "ERROR", "ZAP扫描失败")

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

@celery.task(bind=True, max_retries=5)
def start_scan():
    from flask import current_app as app
    with app.app_context():
        try:
            # 这里是启动扫描的逻辑
            pass
        except Exception as e:
            logger.error(f"启动扫描失败: {str(e)}")
            raise

@celery.task
def test():
    return True