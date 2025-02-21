''' 输入验证'''
import re
from urllib.parse import urlparse
from app.utils.exceptions import BadRequest

class InputValidator:
    @staticmethod
    def validate_url(url: str) -> bool:
        """验证URL格式"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    @staticmethod
    def validate_password(password: str) -> bool:
        """验证密码强度（至少8位，包含大小写字母和数字）"""
        return re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$", password) is not None

    @staticmethod
    def validate_scan_type(scan_type: str):
        """验证扫描类型合法性"""
        allowed_types = ["quick", "full"]
        if scan_type not in allowed_types:
            raise BadRequest(f"无效扫描类型：{scan_type}")