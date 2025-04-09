"""任务管理"""
from celery import chain, chord, group
from flask import g
import requests
from sqlalchemy import func, or_
from app.models.scan_task import ScanTask
from app.extensions import db
from app.models.task_log import TaskLog
from app.models.user import User
from sqlalchemy.orm import joinedload
from app.services.celery_task.celery_tasks import *
from app.utils.exceptions import AppException, ValidationError, Forbidden, InternalServerError, NotFound, Unauthorized
from app.services.scanner.AWVS import AWVS
from celery.result import AsyncResult

class TaskService:
    @staticmethod
    def create_task(user_id: int, task_name: str, target_url: str, scan_type: str, login_url, login_username, login_password):
        # 创建任务记录
        if ScanTask.query.filter_by(task_name=task_name).first():
            raise ValidationError("任务名称已存在")
        
        task = ScanTask(
            user_id=user_id,
            task_name=task_name,
            target_url=target_url,
            scan_type=scan_type,
        )
        if login_url:
            task.login_info=f"{login_url},{login_username},{login_password}"
        try:
            db.session.add(task)
            db.session.commit()
            print(task.task_id)
            target_id = AWVS().add_url(task.task_id, target_url, login_url, login_username, login_password)
            if target_id:
                task.awvs_id = target_id
                db.session.commit()
                TaskService.is_url_accessible(task.task_id, target_url)
                return task
            else:
                db.session.rollback()
                raise InternalServerError(f"AWVS任务创建失败")
        except AppException:
            db.session.rollback()
            task.update_status("failed")
            db.session.commit()
            raise
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"创建任务失败: {e} ")
        
    def is_url_accessible(task_id, url, timeout=5):
        """判断URL是否可访问。"""
        try:
            # 发送 HEAD 请求以减少数据传输量
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            if 200 <= response.status_code < 300:
                TaskLog.add_log(task_id, "INFO", "目标访问成功")
                return True
            else:
                TaskLog.add_log(task_id, "ERROR", f"目标访问失败，返回状态码: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            TaskLog.add_log(task_id, "ERROR", f"目标不可达！")
            return False

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
        """删除任务"""
        try:
            # 检查是否包含运行中的任务
            running_tasks = (db.session.query(ScanTask.task_id).filter(ScanTask.task_id.in_(task_ids), ScanTask.status == "running").all())
            if running_tasks:
                raise ValidationError("不能删除运行中的任务")

            # 检查权限
            invalid_ids = None
            if role != "admin":
                invalid_ids = (db.session.query(ScanTask.task_id).filter(ScanTask.task_id.in_(task_ids), ScanTask.user_id != user_id).all())
            if invalid_ids:
                raise Forbidden("包含无权限操作的任务")

            query = ScanTask.query.filter(ScanTask.task_id.in_(task_ids))
            for task in query.all():
                AWVS().delete(task.awvs_id)
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
            query = db.session.query(
                ScanTask.status,
                func.count(ScanTask.task_id)
            ).group_by(ScanTask.status)
            if g.current_user.get("role") != "admin":
                query = query.filter_by(user_id=int(g.current_user.get("user_id")))
            return query.all()
        except Exception as e:
            raise InternalServerError(f"获取任务状态统计失败: {e}")

    @staticmethod
    def start_scan_task(task_id: int):
        """启动扫描任务"""
        if not TaskService.is_auth(task_id):
            raise Forbidden("无权限访问此任务")
        
        task = ScanTask.query.get(task_id)
        try:
            if task.status != "pending":
                raise ValidationError("任务状态异常，不可启动！")
            # 异步任务组
            task_group_list = []
            task_group_list.append(save_xray_vuls.s(task_id))
            awvs_scan_id = AWVS().start_scan(task_id, task.awvs_id)
            if awvs_scan_id: 
                task_group_list.append(save_awvs_vuls.s(task_id, awvs_scan_id))
                task.awvs_id = awvs_scan_id

            zap_scan_id = None
            if task.login_info:
                list = task.login_info.split(",")
                zap_scan_id = ZAP().start_scan(task_id, task.target_url, task.scan_type, list[0], list[1], list[2])
            else: zap_scan_id = ZAP().start_scan(task_id, task.target_url, task.scan_type)
            print(f"zap_scan_id: {zap_scan_id}; awvs_scan_id:{awvs_scan_id}")

            if zap_scan_id:
                task_group_list.append(save_zap_vuls.s(task_id, zap_scan_id, task.target_url))
                task.zap_id = zap_scan_id

            task_group = group(task_group_list)    
            # 保存任务ID到数据库
            async_result = chord(task_group, update_task_status.s(task_id=task_id), task_protocol=2).apply_async()
            print(async_result)
            task.celery_group_id = async_result.id
            task.celery_task_ids = [t.id for t in async_result.parent.results]  # 获取所有子任务ID
            # 更新任务状态为 running
            task.update_status("running")
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            task.update_status("failed")
            db.session.commit()
            TaskService.stop_scan_task(task_id)
            TaskLog.add_log(task_id, "ERROR", f"启动扫描任务失败")
            raise InternalServerError(f"启动扫描任务失败: {str(e)}")

    @staticmethod
    def stop_scan_task(task_id: int):
        """停止扫描任务"""
        if not TaskService.is_auth(task_id):
            raise Forbidden("无权限操作此任务")
        
        task = ScanTask.query.get(task_id)
        try:
            if task.status == "pending":
                raise ValidationError("任务未在运行中")
            
            # 停止所有 Celery 任务
            if task.celery_group_id:
                group_result = AsyncResult(task.celery_group_id)
                group_result.revoke(terminate=True, signal='SIGTERM')  # 终止顶层任务
            
            if task.celery_task_ids:
                for task_id in task.celery_task_ids:
                    task_result = AsyncResult(task_id)
                    task_result.revoke(terminate=True, signal='SIGTERM')  # 终止子任务

            AWVS().stop_scan(task.awvs_id)
            ZAP().stop_scan(task.zap_id)

            # 更新任务状态
            task.update_status("completed")
            db.session.commit()
            TaskLog.add_log(task_id, "INFO", "任务已手动终止")
            return True
        except AppException:
            db.session.rollback()
            task.update_status("failed")
            db.session.commit()
            raise
        except Exception as e:
            db.session.rollback()
            task.update_status("failed")
            db.session.commit()
            TaskLog.add_log(task_id, "ERROR", f"停止任务失败: {str(e)}")
            raise InternalServerError(f"停止任务失败: {str(e)}")

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
                raise ValidationError(f"任务不存在")
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
