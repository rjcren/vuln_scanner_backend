'''风险评估报告模型'''
from datetime import datetime
from app.extensions import db

class RiskReport(db.Model):
    __tablename__ = 'risk_reports'
    report_id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.task_id'), nullable=False)
    coverage_rate = db.Column(db.Float, nullable=False)
    blind_spot = db.Column(db.Text)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<RiskReport {self.report_id}>'