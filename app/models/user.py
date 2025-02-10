'''用户模型'''
from datetime import datetime
from app.extensions import db

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks = db.relationship('ScanTask', backref='user', lazy=True)
    feedbacks = db.relationship('UserFeedback', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'