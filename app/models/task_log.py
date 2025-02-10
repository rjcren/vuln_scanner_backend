'''任务日志模型'''
from datetime import datetime
from app.extensions import db

class TaskLog(db.Model):
    __tablename__ = 'task_logs'
    log_id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.task_id'), nullable=False)
    log_message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<TaskLog {self.log_id}>'