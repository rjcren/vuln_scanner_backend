"""报告生成"""
import os
import secrets
import string
from playwright.sync_api import sync_playwright
from app.models.risk_report import RiskReport
from sqlalchemy.orm import joinedload
from app.extensions import db
# from fpdf import FPDF
from flask import g, render_template

from app.models.scan_task import ScanTask
from app.services.task import TaskService
from app.utils.exceptions import AppException, Forbidden, InternalServerError, ValidationError

class ReportService:
    _browser = None

    @classmethod
    def _get_browser(cls):
        if not cls._browser or cls._browser.is_connected():
            playwright = sync_playwright().start()
            cls._browser = playwright.chromium.launch(
                headless=True,
                args=["--disable-gpu", "--no-sandbox"]
            )
        return cls._browser

    def generate_report(self, task_id: int, report_type: str = "pdf") -> str:
        """生成漏洞报告 (集成 Playwright)"""
        try:
            if not TaskService.is_auth(task_id):
                raise Forbidden("无权限操作此任务")
            if report_type not in ["pdf", "html"]:
                raise ValidationError("不支持的报告格式")
            
            task = TaskService.get_task(task_id)
            # 检查现有报告缓存
            for report in task.risk_reports:
                if report_type == report.type:
                    return report.path

            task_info = {
                "task_id": task.task_id,
                "task_name": task.task_name,
                "target_url": task.target_url,
                "scan_type": task.scan_type,
                "status": task.status,
                "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "finished_at": task.finished_at.strftime("%Y-%m-%d %H:%M:%S") if task.finished_at else None,
                "login_info": task.login_info.split(',') if task.login_info else None,
                "task_logs": [log.to_dict() for log in task.task_logs] if task.task_logs else [],
                "vulnerabilities": [vuln.to_dict() for vuln in task.vulnerabilities] if task.vulnerabilities else []
            }

            # 生成唯一文件名
            random_string = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(6))
            content = render_template("report_template.html", content=task_info)
            file_path = self.create_dir(f"report_{task_info['task_id']}_{random_string}.{report_type}")

            if report_type == "pdf":
                # 使用 Playwright 生成 PDF
                browser = self._get_browser()
                page = browser.new_page()
                
                try:
                    page.set_content(content)
                    # 配置 PDF 选项
                    pdf_options = {
                        "format": "A4",
                        "print_background": True,
                        "margin": {"top": "20mm", "right": "20mm", "bottom": "20mm", "left": "20mm"},
                        "prefer_css_page_size": True
                    }
                    pdf_bytes = page.pdf(**pdf_options)
                    
                    # 保存 PDF 文件
                    with open(file_path, "wb") as f:
                        f.write(pdf_bytes)
                finally:
                    page.close()
            elif report_type == "html":
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write(content)
            else:
                raise ValidationError("不支持的报告类型")

            # 保存记录到数据库（原有逻辑保留）
            self.__save_file(task_info["task_id"], file_path, report_type)
            return file_path

        except AppException:
            raise
        except Exception as e:
            raise InternalServerError(f"报告生成失败: {str(e)}")
        
    def get_reports(self):
        """获取所有报告"""
        query = RiskReport.query.options(joinedload(RiskReport.task))
        if g.current_user["role"] != "admin":
            query = query.join(RiskReport.task).filter(ScanTask.user_id == g.current_user["user_id"])
        return query.all()
    
    def get_report(self, task_id: int):
        """获取指定任务的报告"""
        if not TaskService.is_auth(task_id):
            raise Forbidden("无权限操作此任务")
        report = RiskReport.query.filter_by(task_id=task_id).first()
        if not report:
            raise ValidationError("报告不存在")
        return report.path
    
    def delete_report(self, report_id: int):
        """删除指定任务的报告"""
        report = RiskReport.query.filter_by(report_id=report_id).first()
        if not TaskService.is_auth(report.task_id):
            raise Forbidden("无权限操作此任务")
        if not report:
            raise ValidationError("报告不存在")
        os.remove(report.path)
        db.session.delete(report)
        db.session.commit()

    def create_dir(self, filename):
        output_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, filename)
        return file_path
    
    def __save_file(self, task_id, file_path, type):
        report = RiskReport(task_id=task_id, path=file_path, type=type)
        db.session.add(report)
        db.session.commit()