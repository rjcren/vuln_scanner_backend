'''安全工具（密码哈希、JWT操作）'''
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask import current_app
from app.utils.exceptions import InvalidToken

class SecurityUtils:
    @staticmethod
    def hash_password(password: str) -> str:
        """生成密码哈希"""
        return generate_password_hash(password, method='scrypt')

    @staticmethod
    def verify_password(hashed_password: str, plain_password: str) -> bool:
        """验证密码"""
        return check_password_hash(hashed_password, plain_password)

    @staticmethod
    def generate_jwt(user_id: int, role: str) -> str:
        """生成JWT令牌"""
        payload = {
            "sub": user_id,
            "role": role,
            "exp": datetime.utcnow() + timedelta(hours=current_app.config['JWT_EXPIRATION_HOURS'])
        }
        return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm="HS256")

    @staticmethod
    def decode_jwt(token: str) -> dict:
        """解析JWT令牌"""
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            raise InvalidToken("令牌已过期")
        except jwt.InvalidTokenError:
            raise InvalidToken("无效令牌")