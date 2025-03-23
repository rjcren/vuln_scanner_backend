from sqlalchemy import inspect
from app.extensions import db
from datetime import datetime

from app.utils.exceptions import InternalServerError

class TaskLog(db.Model):
    __tablename__ = 'task_logs'

    LOG_LEVELS = ('INFO', 'WARNING', 'ERROR')

    log_id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.task_id', ondelete='CASCADE'), nullable=False)
    log_level = db.Column(db.Enum(*LOG_LEVELS), default='INFO')
    log_message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

    task = db.relationship('ScanTask', back_populates='task_logs')

    @classmethod
    def add_log(cls, task_id: int, log_level: str, log_message: str):
        try:
            task_log = cls(
                task_id=task_id, log_level=log_level, log_message=log_message
            )
            db.session.add(task_log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()

    def to_dict(self):
        return {c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs}