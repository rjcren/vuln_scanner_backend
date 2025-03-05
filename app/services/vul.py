from typing import List, Dict, Optional
from app.extensions import db
from app.models import Vulnerability, ScanTask
from app.services.report import ReportService
from app.utils.exceptions import BadRequest, NotFound, InternalServerError
import logging

logger = logging.getLogger(__name__)

class VulService:
    """漏洞管理服务"""

    @staticmethod
    def get_vuls(severity: str = None) -> List[Dict]:
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
            raise InternalServerError(f"无法获取修复建议: {str(e)}")


    @staticmethod
    def _save_results(task_id: int, results: List[Vulnerability]):
        """保存漏洞结果到数据库"""
        for item in results:
            vuln = Vulnerability(
                task_id=task_id,
                vul_type=item["type"],
                severity=item["severity"],
                description=item["description"]
            )
            db.session.add(vuln)
        db.session.commit()