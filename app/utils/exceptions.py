'''自定义异常类'''
from flask import jsonify
from werkzeug.exceptions import HTTPException

class AppException(Exception):
    """应用基础异常"""
    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.code = code

class InvalidCredentials(AppException):
    """无效凭证异常"""
    def __init__(self, message="用户名或密码错误"):
        super().__init__(message, 401)

class UserAlreadyExists(AppException):
    """用户已存在异常"""
    def __init__(self, message="用户名已被注册"):
        super().__init__(message, 409)

class ScanExecutionError(AppException):
    """扫描执行异常"""
    def __init__(self, message="扫描任务执行失败"):
        super().__init__(message, 500)

class InvalidToken(AppException):
    '''无效令牌异常'''
    def __init__(self, message="Invalid token"):
        super().__init__(message, 401)

class TokenGenerationError(AppException):
    '''令牌生成异常'''
    def __init__(self, message="令牌生成异常"):
        super().__init__(message, 500)

class ThreatIntelSyncError(AppException):
    '''威胁情报同步异常'''
    def __init__(self, message="威胁情报同步异常"):
        super().__init__(message, 500)

class ServiceError(HTTPException):
    """服务层异常基类"""
    def __init__(self, message="服务器内部错误"):
        super().__init__(message, 500)

class Unauthorized(ServiceError):
    def __init__(self, message="需要身份验证"):
        super().__init__(message)
        self.code = 401

class Forbidden(ServiceError):
    def __init__(self, message="没有操作权限"):
        super().__init__(message)
        self.code = 403

class NotFound(ServiceError):
    def __init__(self, message="资源不存在"):
        super().__init__(message)
        self.code = 404

# 全局异常处理器（在app初始化时注册）
def handle_service_error(e):
    return jsonify({
        "error": e.description,
        "code": e.code
    }), e.code