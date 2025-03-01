'''认证逻辑'''
import re
import smtplib
from app.models import User
from app.extensions import db
from app.utils import logger
from app.utils.exceptions import *
from flask_mail import Message
from app.extensions import redis_client, mail
import random
import string

class AuthService:
    @staticmethod
    def register_user(email: str, password: str, username: str, role: str = 'user', code: str = None) -> User:
        # 检查用户是否已存在
        if User.query.filter_by(username=username).first():
            raise Conflict(f"用户名 {username} 已被注册")
        stored_captcha = redis_client.get(f"captcha:{email}")
        if not stored_captcha:
            raise ValidationError("验证码已过期或未发送")
        if stored_captcha.decode('utf-8') != code:
            raise ValidationError("验证码错误")
        redis_client.delete(f"captcha:{email}")

        # 创建用户
        user = User(
            username=username,
            password=password,
            email=email,
            role=role
        )
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def authenticate_user(email: str, password: str) -> User:
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            raise BadRequest("账号或密码错误")
        return user

    @staticmethod
    def sendCaptcha(email):
        source = string.digits*4
        captcha = random.sample(source, 4)
        captcha = "".join(captcha)
        try:
            # 验证邮箱格式
            if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
                raise ValidationError("无效的邮箱格式")

            message = Message(subject="漏洞检测系统验证码", recipients=[email], body=f"您的验证码是：{captcha}")
            mail.send(message)
            redis_client.setex(f"captcha:{email}", 300, captcha)
            return True
        except smtplib.SMTPException as e:
            logger.error(f"SMTP协议错误: {str(e)}")
            raise InternalServerError(f"邮件服务器连接失败: {e}")
        except Exception as e:
            logger.error(f"未知邮件错误: {str(e)}", exc_info=True)
            raise InternalServerError("邮件发送服务异常")