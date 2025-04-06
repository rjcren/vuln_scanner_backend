"""装饰器工具类"""
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
        # 获取令牌
        token = request.cookies.get("jwt")
        if not token:
            raise Unauthorized("未授权登录")
        csrf_token_header = request.headers.get("X-CSRF-Token")
        csrf_token_cookie = request.cookies.get("csrf_token")
        if not csrf_token_header or not csrf_token_cookie:
            raise Unauthorized("缺少CSRF Token")
        if csrf_token_header != csrf_token_cookie:
            raise Unauthorized("CSRF Token验证失败")
        try:
            payload = SecurityUtils.decode_jwt(token)
            if payload["iat"] > datetime.now(timezone.utc).timestamp():
                raise Unauthorized("非法请求,请重新登录:非法未来时间Token")
            if payload["exp"] < datetime.now(timezone.utc).timestamp():
                raise Unauthorized(f"令牌已过期:{str(e)}")
            # 存储用户信息到上下文
            user = User.query.get(payload["sub"])
            if not user:
                raise Unauthorized("用户状态异常:用户不存在")
            g.current_user = {
                "user_id": payload["sub"],
                "username": user.username,
                "role": user.role,
            }
        except Exception as e:
            raise Unauthorized(f"认证失败: {str(e)}")
        return f(*args, **kwargs)
    return decorated_function

def require_role(required_role):
    """角色校验装饰器"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not hasattr(g, "current_user"):
                raise Unauthorized("需要先进行认证")
            current_role = g.current_user.get("role", "user")
            if current_role != required_role:
                raise Forbidden("权限不足")
            return func(*args, **kwargs)
        return wrapper
    return decorator

def api_key_required(f):
    """API密钥验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-KEY")
        print(f"API密钥: {api_key}")
        # if not api_key or api_key != current_app.config["API_KEY"]:
        #     raise Unauthorized("无效的API密钥")
        return f(*args, **kwargs)
    return decorated_function