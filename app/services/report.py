'''报告生成'''
from app.models import ScanTask, Vulnerability
from jinja2 import Environment, FileSystemLoader
import pdfkit
import os

class ReportService:
    TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "../../static/templates")

    @staticmethod
    def generate_html_report(task_id: int) -> str:
        """生成HTML格式漏洞报告"""
        env = Environment(loader=FileSystemLoader(ReportService.TEMPLATE_DIR))
        template = env.get_template("report_template.html")

        task = ScanTask.query.get(task_id)
        vulnerabilities = Vulnerability.query.filter_by(task_id=task_id).all()

        return template.render(
            task=task,
            vulnerabilities=vulnerabilities,
            total=len(vulnerabilities)
        )

    @staticmethod
    def generate_pdf_report(html_content: str) -> bytes:
        """将HTML转换为PDF"""
        return pdfkit.from_string(html_content, False)