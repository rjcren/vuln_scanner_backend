"""风险评估报告模型"""
from datetime import datetime, timezone

from flask import jsonify
from sqlalchemy import inspect
from app.extensions import db

class RiskReport(db.Model):
    __tablename__ = "risk_reports"
    report_id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("scan_tasks.task_id", ondelete="CASCADE"), nullable=False)
    coverage_rate = db.Column(db.Float, nullable=False)
    blind_spot = db.Column(db.Text)
    generated_at = db.Column(db.DateTime, default=datetime.now)

    task = db.relationship("ScanTask", back_populates="risk_reports")

    def to_dict(self):
        return {c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs}