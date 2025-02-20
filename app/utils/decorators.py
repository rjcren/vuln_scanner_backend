'''装饰器工具类'''
from functools import wraps
from flask import request, g, jsonify, current_app, abort
from jwt import decode, exceptions
from app.utils.exceptions import InvalidToken, Forbidden
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
            abort(InvalidToken("需要有效的访问令牌"))

        token = auth_header.split(' ')[1]
        try:
            # 解码令牌（示例配置，需与实际配置一致）
            payload = decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=["HS256"]
            )
            # 存储用户信息到上下文
            g.current_user = {
                "user_id": payload["sub"],
                "role": payload.get("role", "user")
            }
        except exceptions.ExpiredSignatureError:
            logger.warning("令牌已过期")
            abort(InvalidToken("令牌已过期"))
        except exceptions.InvalidTokenError:
            logger.warning("无效的令牌")
            abort(InvalidToken("无效的认证令牌"))
        except Exception as e:
            logger.error(f"令牌解析错误: {str(e)}")
            abort(InvalidToken("认证失败"))

        return f(*args, **kwargs)
    return decorated_function

def roles_required(*required_roles):
    """角色权限验证装饰器"""
    def decorator(f):
        @wraps(f)
        @jwt_required  # 依赖JWT验证
        def wrapped_function(*args, **kwargs):
            current_role = g.current_user.get("role")
            if current_role not in required_roles:
                logger.warning(f"角色权限不足: {current_role}")
                raise Forbidden("没有操作权限")
            return f(*args, **kwargs)
        return wrapped_function
    return decorator