from datetime import datetime, timedelta, timezone
from typing import List

from flask import g, render_template
from flask_mail import Mail
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import joinedload
from app.extensions import db
from app.models import Vulnerability, ScanTask
from app.utils.exceptions import AppException, NotFound, InternalServerError, ValidationError
import logging

from app.utils.vul_deduplicator import VulDeduplicator

logger = logging.getLogger(__name__)

class VulService:
    """漏洞管理服务"""
    @staticmethod
    def get_vuls(task_ids: list[int] = None, sources: list = None, severities: List = None, page: int = 1, per_page: int = 10, keyword: str = "", sort_field: str = None, sort_order: str = None):
        """获取指定任务的漏洞列表，支持分页"""
        try:
            query = Vulnerability.query.options(joinedload(Vulnerability.task))

            if g.current_user.get("role") != "admin":
                query = query.filter(Vulnerability.task.has(user_id=int(g.current_user.get("user_id"))))

            # 添加过滤条件
            if task_ids:
                query = query.filter(Vulnerability.task_id.in_(task_ids))
            if sources:
                query = query.filter(Vulnerability.scan_source.in_(sources))
            if severities:
                query = query.filter(Vulnerability.severity.in_(severities))
            if keyword:
                search_pattern = f"%{keyword}%"
                query = query.join(Vulnerability.task).filter(Vulnerability.vul_type.ilike(search_pattern))
            # 排序
            if sort_field and sort_order:
                sort_column = getattr(Vulnerability, sort_field, None)
                if sort_column:
                    if sort_order.lower() == 'asc':
                        query = query.order_by(sort_column.asc())
                    else:
                        query = query.order_by(sort_column.desc())
            
            # 执行分页查询
            pagination = query.paginate(
                page=int(page),
                per_page=int(per_page),
                error_out=False
            )
            return pagination
        except AppException:
            raise
        except Exception as e:
            raise InternalServerError(f"获取漏洞数据失败: {str(e)}")
        
    @staticmethod
    def get_severity_stats():
        """获取漏洞严重程度统计"""
        try:
            query = db.session.query(
                Vulnerability.severity,
                func.count(Vulnerability.vul_id)
            ).group_by(Vulnerability.severity)

            if g.current_user.get("role") != "admin":
                query = query.filter(Vulnerability.task.has(user_id=int(g.current_user.get("user_id"))))
            
            return query.all()
        except Exception as e:
            raise InternalServerError(f"获取漏洞统计失败: {str(e)}")

    @staticmethod
    def get_latest_alerts(hours: int = 24):
        """获取最近24小时的漏洞告警"""
        try:
            recent_time = datetime.now(timezone.utc) - timedelta(hours=hours)  # 使用UTC时间
            query = Vulnerability.query.join(
                Vulnerability.task
            ).filter(
                Vulnerability.time >= recent_time
            ).order_by(Vulnerability.time.desc())
            if g.current_user.get("role") != "admin":
                query = query.filter(Vulnerability.task.has(user_id=int(g.current_user.get("user_id"))))

            return [{
                "vul_id": alert.vul_id,
                "description": alert.description,
                "severity": alert.severity,
                "time": alert.time.isoformat(),
                "task_name": alert.task.task_name if alert.task else "未知任务",
                "target_url": alert.task.target_url if alert.task else "未知url"
            } for alert in query.limit(10).all()]
        except Exception as e:
            raise InternalServerError(f"获取最新告警失败: {str(e)}")

    @staticmethod
    def get_high_risk_count():
        """获取高风险漏洞数量"""
        try:
            query = Vulnerability.query.filter(
                Vulnerability.severity.in_(["critical", "high"])
            )
            if g.current_user.get("role") != "admin":
                query = query.filter(Vulnerability.task.has(user_id=int(g.current_user.get("user_id"))))
            count = query.count()
            return count
        except Exception as e:
            raise InternalServerError(f"获取高风险漏洞数量失败: {str(e)}")

    @staticmethod
    def _save_results(task_id: int, results: List[Vulnerability]):
        """保存漏洞结果到数据库"""
        try:
            if results[0].scan_source != "XRAY":
                existing_vuls = db.session.query(Vulnerability).filter_by(task_id=task_id).all()
                existing_dict = {}
                for vul in existing_vuls:
                    if vul.scan_source not in existing_dict:
                        existing_dict[vul.scan_source] = {}
                    existing_dict[vul.scan_source][vul.scan_id] = vul

                # 初始化去重器并执行去重
                dedup = VulDeduplicator()
                unique_results = dedup.deduplicate(results, existing_dict)
                db.session.add_all(unique_results)
            db.session.add_all(results)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"漏洞保存失败: {str(e)}")
            raise InternalServerError(f"漏洞保存失败: {str(e)}")
        
    def send_alert_email(task_id: int, vulnerabilities: List[Vulnerability]):
        """发送告警邮件"""
        try:
            # 获取任务信息
            task = ScanTask.query.options(joinedload(ScanTask.user)).filter_by(task_id=task_id).first()
            if not task: raise NotFound("任务不存在")
            user = task.user
            html_content = render_template(
                "alert_email_template.html",
                task_name=task.task_name,
                target_url=task.target_url,
                vulnerabilities=vulnerabilities
            )
            from flask_mail import Message
            message = Message(
                subject=f"任务 {task.task_name} 的告警",
                recipients=[user.email],
                html=html_content
            )
            mail = Mail()
            mail.send(message)
            logger.info(f"告警邮件已发送至 {user.email}")
        except Exception as e:
            logger.error(f"发送告警邮件失败: {str(e)}")
            raise InternalServerError(f"发送告警邮件失败: {str(e)}")