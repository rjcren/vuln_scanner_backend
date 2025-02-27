'''装饰器工具类'''
from datetime import datetime, timezone
from functools import wraps
from flask import request, g, current_app
import jwt
from app.models.user import User
from app.utils.exceptions import Unauthorized, Forbidden
from app.utils.security import SecurityUtils
import logging

logger = logging.getLogger(__name__)

def jwt_required(f):
    """JWT认证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 从请求头获取令牌
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            logger.warning("缺少Bearer认证头")
            raise Unauthorized("需要有效的访问令牌")

        token = auth_header.split()[1]
        try:
            payload = SecurityUtils.decode_jwt(token)
            if payload['iat'] > datetime.now(timezone.utc).timestamp():
                raise Unauthorized("非法请求,请重新登录:非法未来时间Token")

            # 存储用户信息到上下文
            user = User.query.get(payload["sub"])
            if not user:
                raise Unauthorized("用户状态异常:token用户不存在")
            g.current_user = {
                "user_id": payload["sub"],
                "role": user.role,
            }
        except jwt.ExpiredSignatureError as e:
            raise Unauthorized(f"令牌已过期:{str(e)}")
        except Exception as e:
            raise Unauthorized(f"认证失败: {str(e)}")

        return f(*args, **kwargs)
    return decorated_function

def require_role(required_role):
    """角色校验装饰器"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 从g对象获取当前用户
            if not hasattr(g, 'current_user'):
                raise Unauthorized("需要先进行认证")
            current_role = g.current_user.get('role', 'user')
            if current_role != required_role:
                logger.warning(f"角色权限不足: 需要{required_role}, 当前{current_role}")
                raise Forbidden("权限不足")
            return func(*args, **kwargs)
        return wrapper
    return decorator