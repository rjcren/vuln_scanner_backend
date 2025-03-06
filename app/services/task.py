"""任务管理"""

from flask import g
from sqlalchemy import or_
from app.models.scan_task import ScanTask
from app.extensions import db
from app.models.task_log import TaskLog
from app.models.user import User
from sqlalchemy.orm import joinedload
from app.services.celery_tasks import CeleryTasks
from app.utils.exceptions import BadRequest, Forbidden, InternalServerError, NotFound


class TaskService:
    @staticmethod
    def create_task(user_id: int, task_name: str, target_url: str, scan_type: str):
        try:
            # 创建任务记录
            task = ScanTask(
                user_id=user_id,
                task_name=task_name,
                target_url=target_url,
                scan_type=scan_type,
            )
            db.session.add(task)
            db.session.commit()
            TaskService.task_log(task.task_id, "INFO", f"创建任务: {task.task_name}")
            return task
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"创建任务失败: {e}")

    @staticmethod
    def get_tasks(role: str, user_id: int, page: int, size: int, keyword: str = None):
        query = None
        base_query = ScanTask.query.options(joinedload(ScanTask.user))

        if role == "admin":
            query = base_query.order_by(ScanTask.created_at.desc())
        else:
            query = base_query.filter_by(user_id=user_id).order_by(
                ScanTask.created_at.desc()
            )
        if keyword:
            # 同时匹配任务名称和用户名
            search_pattern = f"%{keyword}%"
            query = query.join(User).filter(
                or_(
                    ScanTask.task_name.ilike(search_pattern),
                    ScanTask.status.ilike(search_pattern),
                    User.username.ilike(search_pattern),
                )
            )
        return query.paginate(page=page, per_page=size, error_out=False)

    @staticmethod
    def delete_task(task_ids: list, role: str, user_id: int):
        try:
            invalid_ids = None
            if role != "admin":
                invalid_ids = (
                    db.session.query(ScanTask.task_id)
                    .filter(ScanTask.task_id.in_(task_ids), ScanTask.user_id != user_id)
                    .all()
                )
            if invalid_ids:
                raise Forbidden("包含无权限操作的任务")
            deleted_count = ScanTask.query.filter(
                ScanTask.task_id.in_(task_ids)
            ).delete(synchronize_session=False)
            db.session.commit()
            return deleted_count
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"删除任务失败: {e}")

    @staticmethod
    def get_task(task_id: int):
        try:
            task = ScanTask.query.options(joinedload(ScanTask.user)).get(task_id)
            if g.current_user['role'] != "admin" and task.user_id != g.current_user['user_id']:
                raise Forbidden("无权限访问此任务")
            return (
                ScanTask.query.options(
                    joinedload(ScanTask.vulnerabilities),
                    joinedload(ScanTask.risk_reports),
                    joinedload(ScanTask.task_logs),
                )
                .filter_by(task_id=task_id)
                .first()
            )
        except Exception as e:
            raise InternalServerError(f"获取任务失败: {e}")

    @staticmethod
    def task_log(task_id: int, log_level: str, log_message: str):
        try:
            task_log = TaskLog(
                task_id=task_id, log_level=log_level, log_message=log_message
            )
            db.session.add(task_log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"记录任务日志失败: {e}")

    @staticmethod
    def start_scan_task(task_id: int):
        """启动扫描任务"""
        try:
            task = ScanTask.query.get(task_id)
            if not task:
                raise BadRequest("任务未找到")

            # 更新任务状态
            task.update_status('running')
            db.session.commit()

            # 调用celery异步任务
            CeleryTasks.run_scan.delay(task_id)

            TaskService.task_log(task.task_id, "INFO", f"启动扫描任务: {task.task_name}")
            return True

        except Exception as e:
            db.session.rollback()
            TaskService.task_log(task.task_id, "ERROR", f"启动扫描任务失败: {task.task_name}")
            raise InternalServerError(f"启动扫描任务失败: {e}")

    @staticmethod
    def validate_scan_status(task):
        """验证任务状态是否允许扫描"""
        valid_status = ["pending", "failed"]
        if task.status not in valid_status:
            raise BadRequest(f"任务当前状态为 {task.status}，无法重新启动")
