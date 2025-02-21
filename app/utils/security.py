'''安全工具（密码哈希、JWT操作）'''
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask import current_app
from app.utils.exceptions import Unauthorized, InternalServerError
import jwt

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
        try:
            payload = {
                "sub": user_id,
                "role": role,
                "exp": datetime.now() + timedelta(hours=current_app.config['JWT_EXPIRATION_HOURS'])
            }
            return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm="HS256")
        except jwt.PyJWTError as e:
            current_app.logger.error(f"JWT生成失败: {str(e)}")
            raise InternalServerError("令牌生成失败，请检查服务器配置")
        except KeyError as e:
            current_app.logger.error(f"缺少关键配置项: {str(e)}")
            raise InternalServerError("服务器配置不完整")
        except Exception as e:
            current_app.logger.error(f"未知错误: {str(e)}")
            raise InternalServerError("系统内部错误")

    @staticmethod
    def decode_jwt(token: str) -> dict:
        """解析JWT令牌"""
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            raise Unauthorized("令牌已过期")
        except jwt.UnauthorizedError:
            raise Unauthorized("无效令牌")

