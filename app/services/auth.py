"""认证逻辑"""
import re
import smtplib
import logging
from flask import g
from sqlalchemy import or_
from app.models import User
from app.extensions import db, redis_client, mail
from app.utils.exceptions import AppException, BadRequest, Conflict, InternalServerError, Unauthorized, ValidationError
from app.utils.validation import InputValidator
from flask_mail import Message
import random
import string

logger = logging.getLogger(__name__)

class AuthService:

    @staticmethod
    def init_admin():
        """初始化管理员账户"""
        try:
            if not User.query.get(1):
                default_admin_password = "".join(random.choices(string.ascii_letters + string.digits, k=16))
                admin = User(
                    username="admin",
                    password=default_admin_password,  # 密码会在User模型中自动加密
                    email="admin@admin.com",
                    role="admin"
                )
                admin.user_id = 1
                db.session.add(admin)
                db.session.commit()
                # 将初始密码记录到日志中，供系统管理员首次登录使用
                logger.info(f"已创建默认账户。初始密码: {default_admin_password}")
                return default_admin_password
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"初始化管理员账户失败: {str(e)}")

    @staticmethod
    def register_user(email: str, password: str, username: str, role: str = "user", code: str = None) -> User:
        if not InputValidator.validate_password(password):
            Conflict("密码至少8位，包含大小写字母和数字")
        # 检查用户是否已存在
        existing_user = User.query.filter(
            or_(User.username == username, User.email == email)
        ).first()
        if existing_user:
            raise Conflict(f"用户名或邮箱已被注册")
        stored_captcha = redis_client.get(f"captcha:{email}")
        if not stored_captcha:
            raise ValidationError("验证码已过期或未发送")
        if stored_captcha.decode("utf-8") != code:
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
            if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
                raise ValidationError("无效的邮箱格式")

            message = Message(subject="漏洞检测系统验证码", recipients=[email], body=f"您的验证码是：{captcha}")
            mail.send(message)
            redis_client.setex(f"captcha:{email}", 300, captcha)
            return True
        except AppException:
            raise
        except smtplib.SMTPException as e:
            raise InternalServerError(f"邮件服务器连接失败: SMTP协议错误,{e}")
        except Exception as e:
            raise InternalServerError(f"邮件发送服务异常: 未知邮件错误: {str(e)}")

    @staticmethod
    def change_account(user_id:str,username: str):
        try:
            existing_user = User.query.filter(User.username == username).first()
            if existing_user:
                raise Conflict(f"该用户名已被注册：{username}")
            query = AuthService.get_account(user_id)
            query.username =  username
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"修改账号信息失败: {e}")

    @staticmethod
    def change_password(user_id: str, old_password: str, new_password: str):
        try:
            user = User.query.filter_by(user_id=user_id).first()
            if not user.check_password(old_password):
                raise ValidationError("旧密码错误")
            user.password = new_password
            db.session.commit()
        except AppException:
            raise
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"修改密码失败: {e}")
        
    @staticmethod
    def restart_password(user_id: id):
        try:
            user = User.query.filter_by(user_id=user_id).first()
            user.password = user.email
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise InternalServerError(f"重置密码失败: {str(e)}")
        
    @staticmethod
    def admin_reg(email, username, password, role):
        try:
            if not InputValidator.validate_password(password):
                Conflict("密码至少8位，包含大小写字母和数字")
            existing_user = User.query.filter(
                or_(User.username == username, User.email == email)
            ).first()
            if existing_user:
                raise Conflict(f"用户名或邮箱已被注册")
            user = User(
                username=username,
                password=password,
                email=email,
                role=role
            )
            db.session.add(user)
            db.session.commit()
            return user
        except AppException:
            raise
        except Exception as e:
            raise InternalServerError(f"管理员添加失败: {str(e)}")

    @staticmethod
    def get_account(user_id):
        """获取用户对象"""
        try:
            user = User.query.filter_by(user_id=user_id).first()
            if not user:
                raise Unauthorized(f"当前用户异常")
            return user
        except AppException:
            raise
        except Exception as e:
            raise InternalServerError(f"用户身份异常: {str(e)}")

    @staticmethod
    def get_all_user(keyword):
        try:
            query = User.query
            if keyword:
                search_pattern = f"%{keyword}%"
                query = query.filter(
                    or_(
                        User.username.ilike(search_pattern),
                        User.email.ilike(search_pattern)
                    )
                )
            return query.all()
        except Exception as e:
            raise InternalServerError(f"获取用户列表失败: {str(e)}")
        
    @staticmethod
    def delete_user(user_id):
        try:
            user = User.query.get(user_id)
            db.session.delete(user)
            db.session.commit()
        except Exception as e: 
            InternalServerError(f"删除用户失败: {str(e)}")
