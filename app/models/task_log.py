from sqlalchemy import inspect
from app.extensions import db
from datetime import datetime, timezone

from app.utils.exceptions import InternalServerError

class TaskLog(db.Model):
    __tablename__ = 'task_logs'

    LOG_LEVELS = ('INFO', 'WARNING', 'ERROR')

    log_id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.task_id', ondelete='CASCADE'), nullable=False)
    log_level = db.Column(db.Enum(*LOG_LEVELS), default='INFO')
    log_message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    task = db.relationship('ScanTask', back_populates='task_logs')

    @classmethod
    def add_log(cls, task_id: int, log_level: str, log_message: str):
        """添加日志记录"""
        log = cls(
            task_id=task_id,
            log_level=log_level,
            log_message=log_message,
            timestamp=datetime.now(timezone.utc)  # 使用UTC时间
        )
        try:
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e
        return log

    def to_dict(self):
        return {
            "log_id": self.log_id,
            "task_id": self.task_id,
            "level": self.log_level,
            "message": self.log_message,
            "time": self.timestamp.isoformat()  # ISO格式包含时区信息
        }