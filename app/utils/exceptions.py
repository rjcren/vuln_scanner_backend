from flask import jsonify
from werkzeug.exceptions import HTTPException

class AppException(HTTPException):
    """应用基础异常（支持直接返回HTTP响应）"""
    def __init__(self, message: str, code: int = 400):
        super().__init__(description=message, response=None)
        self.code = code

# ========================
# 4xx 客户端错误
# ========================
class InvalidCredentials(AppException):
    """401 无效凭证"""
    def __init__(self, message="用户名或密码错误"):
        super().__init__(message, 401)

class UserAlreadyExists(AppException):
    """409 用户已存在"""
    def __init__(self, message="用户名已被注册"):
        super().__init__(message, 409)

class InvalidToken(AppException):
    """401 无效令牌"""
    def __init__(self, message="无效的认证令牌"):
        super().__init__(message, 401)

# ========================
# 5xx 服务端错误
# ========================
class ServerExecutionError(AppException):
    def __init__(self, message="服务器执行错误"):
        super().__init__(message, 500)

# ========================
# HTTP标准异常补充
# ========================
class Forbidden(AppException):
    """403 禁止访问"""
    def __init__(self, message="没有操作权限"):
        super().__init__(message, 403)

class NotFound(AppException):
    """404 资源不存在"""
    def __init__(self, message="请求的资源不存在"):
        super().__init__(message, 404)

# ========================
# 全局异常处理器
# ========================
def register_error_handlers(app):
    @app.errorhandler(AppException)
    def handle_app_exception(e):
        """统一处理自定义异常"""
        return jsonify({
            "code": e.code,
            "error": e.description
        }), e.code

    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        """覆盖默认的HTML错误页"""
        return jsonify({
            "code": e.code,
            "error": e.description
        }), e.code