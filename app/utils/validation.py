""" 输入验证"""
import re
from urllib.parse import urlparse

class InputValidator:
    @staticmethod
    def validate_url(url: str) -> bool:
        """验证URL格式"""
        url_regex = re.compile(
            r"^(?:http|ftp)s?://"
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"
            r"localhost|"
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"\[?[A-F0-9]*:[A-F0-9:]+\]?)"
            r"(:\d+)?(\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])?$",
            re.IGNORECASE,
        )
        try:
            if not url_regex.match(url):
                return False
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                return False
            return True
        except:
            return False

    @staticmethod
    def validate_password(password: str) -> bool:
        """验证密码强度（至少8位，包含大小写字母和数字）"""
        return re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$", password) is not None
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """验证邮箱格式"""
        email_regex = re.compile(
            r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        )
        return email_regex.match(email)
