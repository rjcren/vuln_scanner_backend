'''用户认证路由'''
from flask import Blueprint, request, jsonify
from app.services.auth import AuthService
from app.utils.security import SecurityUtils
from app.utils.exceptions import InternalServerError, AppException
import logging

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')
        code = data.get('code')

        user = AuthService.register_user(email, password, username, role, code)
        return jsonify({
            "message": "注册成功",
        }), 200
    except AppException as e:
        raise
    except Exception as e:
        logger.error(f"注册失败:{str(e)}", exc_info=True)
        raise InternalServerError("注册失败")

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        user = AuthService.authenticate_user(email, password)
        token = SecurityUtils.generate_jwt(user.user_id, user.username, user.role)
        return jsonify({
            "message": "登录成功",
            "token": token,
            "expires_in": 3600
        }), 200
    except AppException as e:
        raise
    except Exception as e:
        raise InternalServerError(f"登录失败:{e}")

@auth_bp.route('/getcaptcha', methods=['POST'])
def getCaptcha():
    try:
        email = request.get_json().get('email')
        from app.services.auth import AuthService
        res = AuthService.sendCaptcha(email)
        return jsonify({
            "message": "验证码获取成功"
        }), 200
    except AppException as e:
        raise
    except Exception as e:
        raise InternalServerError(f"获取验证码失败{e}")

