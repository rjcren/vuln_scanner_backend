'''认证逻辑'''
from app.models import User, Role
from app.extensions import db
from app.utils.exceptions import *

class AuthService:
    @staticmethod
    def register_user(username: str, password: str, role_name: str) -> User:
        # 检查用户是否已存在
        if User.query.filter_by(username=username).first():
            raise Conflict(f"用户名 {username} 已被注册")

        # 获取角色ID
        role = Role.query.filter_by(role_name=role_name).first()
        if not role:
            raise NotFound(f"角色 {role_name} 不存在")

        # 创建用户
        user = User(
            username=username,
            password_hash=password,
            role_id=role.role_id
        )
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def authenticate_user(username: str, password: str) -> User:
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password_hash(user.password_hash, password):
            raise Unauthorized("用户名或密码错误")
        return user