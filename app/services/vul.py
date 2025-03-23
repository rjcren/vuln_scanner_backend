from datetime import datetime, timedelta
from typing import List

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import joinedload
from app.extensions import db
from app.models import Vulnerability, ScanTask
from app.services.report import ReportService
from app.utils.exceptions import BadRequest, NotFound, InternalServerError
import logging

logger = logging.getLogger(__name__)

class VulService:
    """漏洞管理服务"""
    @staticmethod
    def get_vuls(task_id: int = None, severity: str = None, scan_source: str = None, page: int = 1, per_page: int = 10, keyword: str = ""):
        """获取指定任务的漏洞列表，支持分页"""
        try:
            query = Vulnerability.query.options(joinedload(Vulnerability.task))
            
            # 添加过滤条件
            if task_id:
                query = query.filter_by(task_id=task_id)
            if severity:
                query = query.filter_by(severity=severity)
            if scan_source:
                query = query.filter_by(scan_source=scan_source)
            if keyword:
                search_pattern = f"%{keyword}%"
                query = query.join(Vulnerability.task).filter(
                    or_(
                        Vulnerability.scan_source.ilike(search_pattern),
                        Vulnerability.vul_type.ilike(search_pattern),
                        Vulnerability.severity.ilike(search_pattern),
                        Vulnerability.task.has(ScanTask.task_name.ilike(search_pattern)),
                        Vulnerability.task.has(ScanTask.target_url.ilike(search_pattern))
                    )
                )
            # 按时间倒序排序
            query = query.order_by(Vulnerability.vul_id.desc())
            
            # 执行分页查询
            pagination = query.paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )
            return pagination
        except BadRequest:
            raise
        except Exception as e:
            raise InternalServerError(f"获取漏洞数据失败: {str(e)}")
        
    @staticmethod
    def get_severity_stats():
        """获取漏洞严重程度统计"""
        try:
            status = db.session.query(
                Vulnerability.severity,
                func.count(Vulnerability.vul_id)
            ).group_by(Vulnerability.severity).all()
            
            return status
        except Exception as e:
            raise InternalServerError(f"获取漏洞统计失败: {str(e)}")

    @staticmethod
    def get_latest_alerts(hours: int = 24):
        """获取最近24小时的漏洞告警"""
        try:
            recent_time = datetime.now() - timedelta(hours=hours)
            alerts = Vulnerability.query.join(
                Vulnerability.task
            ).filter(
                Vulnerability.time >= recent_time
            ).order_by(Vulnerability.time.desc()).limit(10).all()
            
            return [{
                "vul_id": alert.vul_id,
                "description": alert.description,
                "severity": alert.severity,
                "time": alert.time.isoformat(),
                "task_name": alert.task.task_name if alert.task else "未知任务",
                "target_url": alert.task.target_url if alert.task else "未知url"
            } for alert in alerts]
        except Exception as e:
            raise InternalServerError(f"获取最新告警失败: {str(e)}")

    @staticmethod
    def get_high_risk_count():
        """获取高风险漏洞数量"""
        try:
            query = Vulnerability.query.filter(
                Vulnerability.severity.in_(["critical", "high"])
            )
            count = query.count()
            return count
        except Exception as e:
            raise InternalServerError(f"获取高风险漏洞数量失败: {str(e)}")

    @staticmethod
    def _save_results(task_id: int, results: List[Vulnerability]):
        """保存漏洞结果到数据库"""
        try:
            existing_scan_ids = db.session.query(Vulnerability.scan_id).filter_by(task_id=task_id).all()
            existing_scan_ids = [item[0] for item in existing_scan_ids]

            for item in results:
                if item.scan_id not in existing_scan_ids:
                    item.task_id = task_id
                    db.session.add(item)
                
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"漏洞保存失败: {str(e)}")
            raise InternalServerError(f"漏洞保存失败: {str(e)}")