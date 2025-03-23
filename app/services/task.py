"""任务管理"""
from celery import chain, chord, group
from flask import g
from sqlalchemy import func, or_
from app.models.scan_task import ScanTask
from app.extensions import db
from app.models.task_log import TaskLog
from app.models.user import User
from sqlalchemy.orm import joinedload
from app.celery_task.celery_tasks import *
from app.services.report import ReportService
from app.utils.exceptions import AppException, BadRequest, Forbidden, InternalServerError, NotFound, Unauthorized
from app.services.scanner.AWVS import AWVS

class TaskService:
    @staticmethod
    def create_task(user_id: int, task_name: str, target_url: str, scan_type: str):
        # 创建任务记录
        task = ScanTask(
            user_id=user_id,
            task_name=task_name,
            target_url=target_url,
            scan_type=scan_type,
        )
        try:
            db.session.add(task)
            db.session.commit()
            print(task.task_id)
            target_id = AWVS.add_url(task.task_id, target_url)
            if target_id:
                task.awvs_id = target_id
                db.session.commit()
                return task
            else:
                db.session.rollback()
                raise InternalServerError(f"任务创建失败:{e}")
        except AppException:
            raise
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"创建任务失败: {e} ")

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
                    ScanTask.target_url.ilike(search_pattern),
                    ScanTask.scan_type.ilike(search_pattern),
                    User.username.ilike(search_pattern),
                )
            )
        return query.paginate(page=page, per_page=size, error_out=False)

    @staticmethod
    def delete_task(task_ids: list, role: str, user_id: int):
        """删除任务，不能删除运行中的任务"""
        try:
            # 检查是否包含运行中的任务
            running_tasks = (db.session.query(ScanTask.task_id).filter(ScanTask.task_id.in_(task_ids), ScanTask.status == "running").all())
            if running_tasks:
                raise BadRequest("不能删除运行中的任务")

            # 检查权限
            invalid_ids = None
            if role != "admin":
                invalid_ids = (db.session.query(ScanTask.task_id).filter(ScanTask.task_id.in_(task_ids), ScanTask.user_id != user_id).all())
            if invalid_ids:
                raise Forbidden("包含无权限操作的任务")

            query = ScanTask.query.filter(ScanTask.task_id.in_(task_ids))
            for task in query.all():
                AWVS.delete(task.awvs_id)
            deleted_count = query.delete(synchronize_session=False)
            db.session.commit()
            return deleted_count
        except AppException:
            raise
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"删除任务失败: {e}")

    @staticmethod
    def get_task(task_id: int):
        try:
            if(not TaskService.is_auth(task_id)): raise Forbidden("无权限访问此任务")
            return (
                ScanTask.query.options(
                    joinedload(ScanTask.vulnerabilities),
                    joinedload(ScanTask.risk_reports),
                    joinedload(ScanTask.task_logs),
                )
                .filter_by(task_id=task_id)
                .first()
            )
        except AppException: raise
        except Exception as e:
            raise InternalServerError(f"获取任务失败: {e}")
        
    @staticmethod
    def get_task_status_stats():
        """获取任务状态统计"""
        try:
            status = db.session.query(
                ScanTask.status,
                func.count(ScanTask.task_id)
            ).group_by(ScanTask.status).all()
            return status
        except Exception as e:
            raise InternalServerError(f"获取任务状态统计失败: {e}")

    @staticmethod
    def start_scan_task(task_id: int):
        """启动扫描任务"""
        if not TaskService.is_auth(task_id):
            raise Forbidden("无权限访问此任务")
        
        try:
            task = ScanTask.query.get(task_id)
            scan_id = AWVS.start_scan(task_id, task.awvs_id)
            
            if not scan_id:
                TaskLog.add_log(task_id, "ERROR", "启动扫描任务失败（AWVS返回无效ID）")
                task.update_status("failed")
                db.session.commit()
                raise BadRequest("AWVS 扫描任务启动失败")
            
            # 更新任务状态为 running
            task.awvs_id = scan_id
            task.update_status("running")
            db.session.commit()
            
            # 异步任务组
            task_group = group(
                save_awvs_vuls.s(task_id, scan_id),
                save_xray_vuls.s(task_id)
            )
            # 当 group 中的所有任务完成后，触发 update_task_status
            chord(task_group, update_task_status.s(task_id=task_id)).apply_async()
            
            return True
        except Exception as e:
            db.session.rollback()
            task = ScanTask.query.get(task_id)
            task.update_status("failed")
            TaskLog.add_log(task_id, "ERROR", f"启动扫描任务失败: {str(e)}")
            raise InternalServerError(f"启动扫描任务失败: {e}")

    @staticmethod
    def get_running_count() -> int:
        """获取运行中的任务数量"""
        try:
            query = ScanTask.query.filter_by(status="running")
            if g.current_user.get("role") != "admin":
                query = query.filter_by(user_id=int(g.current_user.get("user_id")))
                
            return query.count()
        except Exception as e:
            raise InternalServerError(f"获取运行中任务数量失败: {str(e)}")

    @staticmethod
    def is_auth(task_id):
        """判断用户身份"""
        try:
            task = ScanTask.query.options(joinedload(ScanTask.user)).get(task_id)
            if not task:
                raise BadRequest(f"任务不存在")
            # 检查当前用户上下文是否存在
            if not hasattr(g, "current_user"):
                return Unauthorized("用户上下文异常！")
            # 管理员具有所有权限
            if g.current_user.get("role") == "admin":
                return True
            # 验证任务所有者
            return task.user_id == int(g.current_user.get("user_id", 0))
        except AppException:
            raise
        except Exception as e:
            raise InternalServerError(f"判断用户身份失败: {str(e)}")

    
    @staticmethod
    def generate_report(task_id: int, report_type: str = "pdf") -> str:
        """生成漏洞报告"""
        try:
            if format == "pdf":
                report_path = ReportService.generate_report(task_id, report_type)
                return report_path
            else:
                raise BadRequest("不支持的报告格式")
        except Exception as e:
            raise InternalServerError(f"报告生成失败: {str(e)}")
