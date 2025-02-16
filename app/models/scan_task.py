'''扫描任务模型'''
from datetime import datetime
from app.extensions import db

class ScanTask(db.Model):
    __tablename__ = 'scan_tasks'
    task_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    target_url = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Enum('pending', 'running', 'completed', 'failed'), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.now)
    finished_at = db.Column(db.DateTime)
    vulnerabilities = db.relationship('Vulnerability', backref='task', lazy=True)
    logs = db.relationship('TaskLog', backref='task', lazy=True)
    fuzz_results = db.relationship('FuzzResult', backref='task', lazy=True)
    risk_reports = db.relationship('RiskReport', backref='task', lazy=True)

    def __repr__(self):
        return f'<ScanTask {self.task_id}>'

    def start_scan(self):
        """启动扫描（供外部调用）"""
        from app.services.scanner import ScanService
        ScanService.execute_task(self.id)