from app.extensions import db
from datetime import datetime

class TaskLog(db.Model):
    __tablename__ = 'task_logs'

    LOG_LEVELS = ('INFO', 'WARNING', 'ERROR', 'DEBUG')

    log_id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.task_id'), nullable=False)
    log_level = db.Column(db.Enum(*LOG_LEVELS), default='INFO')
    log_message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

    task = db.relationship('ScanTask', back_populates='logs', ondelete='CASCADE')