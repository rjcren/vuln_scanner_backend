"""报告生成"""
from app.models.scan_task import ScanTask
from app.models.vulnerability import Vulnerability
from app.extensions import db
# from fpdf import FPDF
from flask import render_template

class ReportService:
    @staticmethod
    def generate_report(task_id, report_type="pdf"):
        # 查询任务信息
        task = db.session.query(ScanTask).filter_by(task_id=task_id).first()
        if not task:
            raise ValueError("任务不存在")

        # 查询相关漏洞信息
        vulnerabilities = db.session.query(Vulnerability).filter_by(task_id=task_id).all()

        # 生成报告内容
        report_content = {
            "task_name": task.task_name,
            "target_url": task.target_url,
            "status": task.status,
            "created_at": task.created_at,
            "finished_at": task.finished_at,
            "vulnerabilities": [vul.to_dict() for vul in vulnerabilities]
        }

        # if report_type == "pdf":
        #     return generate_pdf_report(report_content)
        # elif report_type == "html":
        #     return generate_html_report(report_content)
        # else:
        #     raise ValueError("不支持的报告类型")

    # def generate_pdf_report(content):
    #     pdf = FPDF()
    #     pdf.add_page()
    #     pdf.set_font("Arial", size=12)

    #     # 添加任务信息
    #     pdf.cell(200, 10, txt=f"任务名称: {content["task_name"]}", ln=True)
    #     pdf.cell(200, 10, txt=f"目标URL: {content["target_url"]}", ln=True)
    #     pdf.cell(200, 10, txt=f"状态: {content["status"]}", ln=True)
    #     pdf.cell(200, 10, txt=f"创建时间: {content["created_at"]}", ln=True)
    #     pdf.cell(200, 10, txt=f"完成时间: {content["finished_at"]}", ln=True)

    #     # 添加漏洞信息
    #     pdf.cell(200, 10, txt="漏洞信息:", ln=True)
    #     for vul in content["vulnerabilities"]:
    #         pdf.cell(200, 10, txt=f"漏洞类型: {vul["vul_type"]}, 严重性: {vul["severity"]}", ln=True)
    #         pdf.cell(200, 10, txt=f"描述: {vul["description"]}", ln=True)
    #         pdf.cell(200, 10, txt=f"解决方案: {vul["solution"]}", ln=True)

    #     # 保存PDF文件
    #     pdf_file_path = f"report_{content["task_name"]}.pdf"
    #     pdf.output(pdf_file_path)
    #     return pdf_file_path

    @staticmethod
    def generate_html_report(content):
        # 使用Flask的render_template生成HTML
        html_content = render_template("report_template.html", content=content)
        html_file_path = f"report_{content["task_name"]}.html"
        with open(html_file_path, "w") as file:
            file.write(html_content)
        return html_file_path