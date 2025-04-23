"""用户反馈模型"""
from datetime import datetime, timezone
from app.extensions import db

class UserFeedback(db.Model):
    __tablename__ = "user_feedbacks"
    feedback_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey("scan_tasks.task_id"), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum("pending", "resolved", "rejected"), default="pending", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    user = db.relationship('User', backref='feedbacks')
    task = db.relationship('ScanTask', back_populates='feedbacks')

    def __repr__(self):
        return f"<UserFeedback {self.feedback_id}>"