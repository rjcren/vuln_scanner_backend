"""报告生成"""
import os
import secrets
import string
import pdfkit
from app.models.risk_report import RiskReport
from sqlalchemy.orm import joinedload
from app.extensions import db
# from fpdf import FPDF
from flask import g, render_template

from app.models.scan_task import ScanTask
from app.services.task import TaskService
from app.utils.exceptions import AppException, Forbidden, InternalServerError, ValidationError

class ReportService:
    def generate_report(self, task_id: int, report_type: str = "pdf") -> str:
        """生成漏洞报告"""
        try:
            if not TaskService.is_auth(task_id):
                raise Forbidden("无权限操作此任务")
            if report_type not in ["pdf", "html"]:
                raise ValidationError("不支持的报告格式")
            
            task = TaskService.get_task(task_id)
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

            characters = string.ascii_letters + string.digits
            random_string = ''.join(secrets.choice(characters) for _ in range(6))
            content = render_template("report_template.html", content=task_info)
            file_path = self.create_dir(f"report_{task_info['task_id']}_{random_string}.{report_type}")
            if report_type == "pdf":
                pdfkit.from_string(content, file_path)
            elif report_type == "html":
                with open(file_path, "w") as file:
                    file.write(content)
            else:
                raise ValidationError("不支持的报告类型")
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