'''中间件'''
from flask import request, g
from app.utils.security import SecurityUtils
from app.utils.exceptions import InvalidToken
from app.models.role import Role

class AuthMiddleware:
    @staticmethod
    def jwt_required(func):
        """JWT认证中间件"""
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if not token:
                raise InvalidToken("缺少认证令牌")

            role = Role.query.filter_by(role_name=payload["role"]).first()
            if not role:
                raise InvalidToken("无效用户角色")

            try:
                payload = SecurityUtils.decode_jwt(token)
                g.current_user = {
                    "user_id": payload["sub"],
                    "role": payload["role"]
                }
            except InvalidToken as e:
                raise e

            return func(*args, **kwargs)
        return wrapper