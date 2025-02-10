'''自定义异常类'''
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