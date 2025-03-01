"""任务管理"""

from sqlalchemy import or_
from app.models import ScanTask
from app.extensions import db
from app.models.user import User
from app.tasks.scan_tasks import run_scan_task
from sqlalchemy.orm import joinedload

from app.utils.exceptions import InternalServerError


class TaskService:
    @staticmethod
    def create_task(user_id: int, task_name: str, target_url: str, scan_type: str) -> ScanTask:
        try:
            # 创建任务记录
            task = ScanTask(user_id=user_id, task_name=task_name, target_url=target_url, scan_type=scan_type)
            db.session.add(task)
            db.session.commit()
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
            query = query.join(User).filter(or_(
                    ScanTask.task_name.ilike(search_pattern),
                    ScanTask.status.ilike(search_pattern),
                    User.username.ilike(search_pattern),
                )
            )
        return query.paginate(page=page, per_page=size, error_out=False)

    @staticmethod
    def delete_task(task_ids: list):
        try:
            tasks = ScanTask.query.filter(ScanTask.task_id.in_(task_ids)).all()
            for task in tasks:
                db.session.delete(task)
                db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"删除任务失败: {e}")

