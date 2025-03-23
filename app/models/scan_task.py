"""扫描任务模型"""
from datetime import datetime, timezone
from app.extensions import db
from app.utils.exceptions import BadRequest, InternalServerError

class ScanTask(db.Model):
    __tablename__ = "scan_tasks"
    task_id = db.Column(db.Integer, primary_key=True)
    awvs_id = db.Column(db.String(40), unique=True)
    task_name = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    target_url = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.Enum("full", "quick"), default="quick", nullable=False)
    status = db.Column(db.Enum("pending", "running", "completed", "failed"), default="pending", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    finished_at = db.Column(db.DateTime)
    vulnerabilities = db.relationship("Vulnerability", back_populates="task", cascade="all, delete", lazy="select")
    risk_reports = db.relationship("RiskReport", back_populates="task", cascade="all, delete", lazy="select")
    task_logs = db.relationship("TaskLog", back_populates="task", cascade="all, delete", lazy="select")

    def update_status(self, new_status):
        valid_transitions = {
            "pending": ["running"],
            "running": ["completed", "failed"],
            "failed": ["running", "pending"],
            "completed": []
        }
        if new_status not in valid_transitions[self.status]:
            raise BadRequest(f"无法从 {self.status} 转换到 {new_status}")
        self.status = new_status
        db.session.commit()