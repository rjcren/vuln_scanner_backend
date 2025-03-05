'''用户模型'''
from datetime import datetime, timezone
from app.extensions import db
from app.utils.security import SecurityUtils

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    _password_hash = db.Column("password", db.String(255), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    role = db.Column(db.Enum('user', 'admin'), default='user', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    tasks = db.relationship('ScanTask', backref='user', lazy=True)
    feedbacks = db.relationship('UserFeedback', backref='user', lazy=True)

    def __init__(self, username, email, password, role='user'):
        self.email = email
        self.username = username
        self.password = password
        self.role = role

    @property
    def password(self):
        return self._password_hash

    @password.setter
    def password(self, password):
        """设置密码"""
        self._password_hash = SecurityUtils.hash_password(password)

    def check_password(self, password):
        """验证密码"""
        return SecurityUtils.verify_password(self._password_hash, password)

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "email": self.email,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }