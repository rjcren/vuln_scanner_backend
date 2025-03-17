from datetime import datetime, timedelta
from typing import List

from sqlalchemy import func
from app.extensions import db
from app.models import Vulnerability, ScanTask
from app.services.report import ReportService
from app.utils.exceptions import BadRequest, NotFound, InternalServerError
import logging

logger = logging.getLogger(__name__)

class VulService:
    """漏洞管理服务"""

    @staticmethod
    def get_vuls(severity: str = None):
        """获取指定任务的漏洞列表"""
        try:
            query = Vulnerability.query.all()
            if severity:
                query = query.filter_by(severity=severity)
            vul = query.all()
            if not vul:
                raise BadRequest("未找到相关漏洞记录")
            return vul
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
                Vulnerability.severity.in_(['critical', 'high'])
            )
            # 添加调试日志
            logger.debug(f"SQL查询语句: {str(query.statement)}")
            count = query.count()
            logger.debug(f"查询结果数量: {count}")
            return count
        except Exception as e:
            logger.error(f"获取高风险漏洞数量失败: {str(e)}")
            raise InternalServerError(f"获取高风险漏洞数量失败: {str(e)}")

    @staticmethod
    def generate_report(task_id: int, format: str = "pdf") -> str:
        """生成漏洞报告"""
        try:
            task = ScanTask.query.get_or_404(task_id)
            vulnerabilities = VulService.get_vuls(task_id)

            if format == "pdf":
                report_path = ReportService.generate_pdf_report(
                    title=f"漏洞扫描报告 - 任务{task_id}",
                    content={
                        "target": task.target_url,
                        "vulnerabilities": vulnerabilities
                    }
                )
                return report_path
            else:
                raise BadRequest("不支持的报告格式")
        except Exception as e:
            raise InternalServerError(f"报告生成失败: {str(e)}")

    @staticmethod
    def get_fix_suggestions(vul_id: int):
        """获取漏洞修复建议"""
        try:
            vul = Vulnerability.query.get_or_404(vul_id)
            # 示例逻辑，实际应集成修复知识库
            return {
                "solution": vul.solution or "请升级到最新版本",
                "reference": f"https://nvd.nist.gov/vuln/detail/{vul.cve_id}"
            }
        except Exception as e:
            raise InternalServerError(f"无法获取修复建议: {str(e)}")


    @staticmethod
    def _save_results(task_id: int, results: List[Vulnerability]):
        """保存漏洞结果到数据库"""
        for item in results:
            vuln = Vulnerability(
                task_id=task_id,
                scan_source=item["scan_source"],
                cve_id=item['cve_id'],
                severity=item["severity"],
                description=item["description"] or '暂无',
                solution=item['solution'] or '暂无'
            )
            db.session.add(vuln)
        db.session.commit()