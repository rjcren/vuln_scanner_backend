from flask import jsonify
from werkzeug.exceptions import HTTPException

class AppException(HTTPException):
    """应用基础异常（所有自定义异常的基类）"""
    def __init__(self, message: str, code: int):
        super().__init__(description=message, response=None)
        self.code = code

# ========================
# 4xx 客户端错误
# ========================
class BadRequest(AppException):
    """400 错误请求"""
    def __init__(self, message="请求参数错误"):
        super().__init__(message, 400)

class Unauthorized(AppException):
    """401 未认证"""
    def __init__(self, message="需要身份验证"):
        super().__init__(message, 401)

class InvalidCredentials(Unauthorized):
    """401 凭证无效"""
    def __init__(self, message="用户名或密码错误"):
        super().__init__(message)

class InvalidToken(Unauthorized):
    """401 令牌无效"""
    def __init__(self, message="无效的认证令牌"):
        super().__init__(message)

class Forbidden(AppException):
    """403 禁止访问"""
    def __init__(self, message="没有操作权限"):
        super().__init__(message, 403)

class NotFound(AppException):
    """404 资源不存在"""
    def __init__(self, message="请求的资源不存在"):
        super().__init__(message, 404)

class MethodNotAllowed(AppException):
    """405 方法不允许"""
    def __init__(self, message="请求方法不允许"):
        super().__init__(message, 405)

class Conflict(AppException):
    """409 资源冲突"""
    def __init__(self, message="资源状态冲突"):
        super().__init__(message, 409)

class UnsupportedMediaType(AppException):
    """415 不支持的媒体类型"""
    def __init__(self, message="不支持的Content-Type"):
        super().__init__(message, 415)

class ValidationError(AppException):
    """422 参数验证失败"""
    def __init__(self, message="参数验证失败"):
        super().__init__(message, 422)

class TooManyRequests(AppException):
    """429 请求过多"""
    def __init__(self, message="请求过于频繁"):
        super().__init__(message, 429)

# ========================
# 5xx 服务端错误
# ========================
class InternalServerError(AppException):
    """500 服务器内部错误"""
    def __init__(self, message="服务器内部错误"):
        super().__init__(message, 500)

class NotImplemented(AppException):
    """501 未实现功能"""
    def __init__(self, message="功能未实现"):
        super().__init__(message, 501)

class BadGateway(AppException):
    """502 网关错误"""
    def __init__(self, message="上游服务不可用"):
        super().__init__(message, 502)

class ServiceUnavailable(AppException):
    """503 服务不可用"""
    def __init__(self, message="服务暂时不可用"):
        super().__init__(message, 503)

class GatewayTimeout(AppException):
    """504 网关超时"""
    def __init__(self, message="请求处理超时"):
        super().__init__(message, 504)

# ========================
# 全局异常处理器
# ========================
def register_error_handlers(app):
    @app.errorhandler(AppException)
    def handle_app_exception(e):
        """统一处理自定义异常"""
        return jsonify({
            "code": e.code,
            "error": e.__class__.__name__,
            "message": e.description
        }), e.code

    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        """覆盖默认错误处理"""
        return jsonify({
            "code": e.code,
            "error": e.name,
            "message": e.description
        }), e.code

    @app.errorhandler(Exception)
    def handle_general_exception(e):
        """处理未捕获的异常"""
        app.logger.error(f"Unhandled exception: {str(e)}")
        return jsonify({
            "code": 500,
            "error": "InternalServerError",
            "message": "服务器发生未知错误"
        }), 500