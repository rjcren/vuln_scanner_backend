from typing import List, Dict, Optional
from app.extensions import db
from app.models import Vulnerability, ScanTask
from app.services.report import ReportService
from app.utils.exceptions import NotFound, InternalServerError
from flask import abort
import logging

logger = logging.getLogger(__name__)

class VulService:
    """漏洞管理服务"""

    @staticmethod
    def get_vulnerabilities(task_id: int, severity: str = None) -> List[Dict]:
        """获取指定任务的漏洞列表"""
        try:
            query = Vulnerability.query.filter_by(task_id=task_id)
            if severity:
                query = query.filter_by(severity=severity)

            vulnerabilities = query.all()
            if not vulnerabilities:
                abort(NotFound("未找到相关漏洞记录"))

            return [{
                "vul_id": vul.vul_id,
                "cve_id": vul.cve_id,
                "severity": vul.severity,
                "description": vul.description
            } for vul in vulnerabilities]
        except Exception as e:
            logger.error(f"查询漏洞失败: {str(e)}")
            abort(ServiceError("获取漏洞数据失败"))

    @staticmethod
    def generate_report(task_id: int, format: str = "pdf") -> str:
        """生成漏洞报告"""
        try:
            task = ScanTask.query.get_or_404(task_id)
            vulnerabilities = VulService.get_vulnerabilities(task_id)

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
                abort(ValueError("不支持的报告格式"))
        except Exception as e:
            logger.error(f"生成报告失败: {str(e)}")
            abort(ServiceError("报告生成失败"))

    @staticmethod
    def get_fix_suggestions(vul_id: int) -> Dict:
        """获取漏洞修复建议"""
        try:
            vul = Vulnerability.query.get_or_404(vul_id)
            # 示例逻辑，实际应集成修复知识库
            return {
                "solution": vul.solution or "请升级到最新版本",
                "reference": f"https://nvd.nist.gov/vuln/detail/{vul.cve_id}"
            }
        except Exception as e:
            logger.error(f"获取修复建议失败: {str(e)}")
            abort(ServiceError("无法获取修复建议"))