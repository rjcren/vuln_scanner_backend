'''报告生成工具'''
from jinja2 import Environment, FileSystemLoader
import pdfkit
from pathlib import Path

class ReportGenerator:
    TEMPLATE_DIR = Path(__file__).parent.parent / "static/templates"

    @classmethod
    def generate_html_report(cls, task_data: dict) -> str:
        """生成HTML报告"""
        env = Environment(loader=FileSystemLoader(str(cls.TEMPLATE_DIR)))
        template = env.get_template("report_template.html")
        return template.render(task_data=task_data)

    @classmethod
    def convert_to_pdf(cls, html_content: str) -> bytes:
        """转换为PDF"""
        options = {
            "encoding": "UTF-8",
            "quiet": ""
        }
        return pdfkit.from_string(html_content, False, options=options)