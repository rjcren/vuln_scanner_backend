from datetime import datetime
import logging
from app.extensions import celery, db
from app.models.task_log import TaskLog
from app.models.scan_task import ScanTask
from app.services.scanner.AWVS import AWVS
from app.services.scanner.ZAP import ZAP
from app.utils.exceptions import AppException, ValidationError

logger = logging.getLogger(__name__)

@celery.task(bind=True, max_retries=200)
def save_awvs_vuls(self, task_id, scan_id):
    try:
        res = AWVS().save_vuls(task_id, scan_id)
        if not res:
            raise self.retry(countdown=30)
        return True
    except AppException:
        raise 
    except Exception as e:
        logger.error(f"AWVS celery error: {e}")
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
            if task.status != "running" or not group_results: return
            scan_results = {"awvs": False, "zap": False, "xray": False}
            # 解析各工具扫描结果
            for idx, result in enumerate(group_results):
                if task.awvs_id and idx == 0:
                    scan_results["awvs"] = bool(result)
                    TaskLog.add_log(task_id, "INFO" if result else "ERROR",
                                  "AWVS扫描成功" if result else "AWVS扫描失败")
                elif task.zap_id and ((task.scan_type == "full" and idx == 2) or 
                                    (task.scan_type != "full" and idx == 1)):
                    scan_results["zap"] = bool(result)
                    TaskLog.add_log(task_id, "INFO" if result else "ERROR",
                                  "ZAP扫描成功" if result else "ZAP扫描失败")
                elif task.xray_port and idx == 1:
                    scan_results["xray"] = bool(result)
                    TaskLog.add_log(task_id, "INFO" if result else "ERROR",
                                  "Xray扫描成功" if result else "Xray扫描失败")
            is_success = any([
                scan_results["awvs"] and task.awvs_id,
                scan_results["zap"] and task.zap_id,
                scan_results["xray"] and task.xray_port
            ])

            task.finished_at = datetime.now()
            task.update_status("completed")
            db.session.commit()
            if is_success: TaskLog.add_log(task_id, "INFO", "扫描结束")
            else: TaskLog.add_log(task_id, "WARNING", "扫描结束，部分工具扫描存在问题，请查看系统日志")
        except Exception as e:
            db.session.rollback()
            if task:
                task.finished_at = datetime.now()
                task.update_status("failed")
                db.session.commit()
            TaskLog.add_log(task_id, "ERROR", f"更新任务状态失败: {str(e)}")
            raise

@celery.task
def test():
    return True