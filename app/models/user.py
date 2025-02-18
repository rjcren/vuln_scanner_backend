'''用户模型'''
from datetime import datetime
from app.extensions import db
from app.utils.security import SecurityUtils

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    _password_hash = db.Column("password", db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    tasks = db.relationship('ScanTask', backref='user', lazy=True)
    feedbacks = db.relationship('UserFeedback', backref='user', lazy=True)

    def __init__(self, username, password, role_id):
        self.username = username
        self.password = password
        self.role_id = role_id

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
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role.role_name if self.role else None
        }

    def __repr__(self):
        return f'<User {self.username}>'