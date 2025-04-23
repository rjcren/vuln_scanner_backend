"""扫描任务模型"""
from datetime import datetime, timezone
from app.extensions import db
from app.utils.exceptions import ValidationError

class ScanTask(db.Model):
    __tablename__ = "scan_tasks"
    task_id = db.Column(db.Integer, primary_key=True)
    awvs_id = db.Column(db.String(40), unique=True)
    zap_id = db.Column(db.String(10), unique=True)
    xray_port = db.Column(db.Integer, nullable=True)
    task_name = db.Column(db.String(255), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    target_url = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.Enum("full", "xss", "sql", "pass", "quick"), default="quick", nullable=False)
    status = db.Column(db.Enum("pending", "running", "completed", "failed"), default="pending", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    finished_at = db.Column(db.DateTime)
    celery_group_id = db.Column(db.String(255), comment="存储任务组ID")
    celery_task_ids = db.Column(db.JSON, comment="存储所有子任务ID")
    login_info = db.Column(db.String(255))

    vulnerabilities = db.relationship("Vulnerability", back_populates="task", cascade="all, delete", lazy="select")
    risk_reports = db.relationship("RiskReport", back_populates="task", cascade="all, delete", lazy="select")
    task_logs = db.relationship("TaskLog", back_populates="task", cascade="all, delete", lazy="select")
    feedbacks = db.relationship("UserFeedback", back_populates="task", cascade="all, delete", lazy="select")

    def update_status(self, new_status):
        valid_transitions = {
            "pending": ["running", "failed"],
            "running": ["completed", "failed"],
            "failed": ["completed"],
            "completed": ["failed"]
        }
        if new_status not in valid_transitions[self.status]:
            raise ValidationError(f"无法从 {self.status} 转换到 {new_status}")
        self.status = new_status
        db.session.commit()