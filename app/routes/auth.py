'''用户认证路由'''
from flask import Blueprint, request, jsonify
from app.services.auth import AuthService
from app.utils.security import SecurityUtils
from app.utils.exceptions import InternalServerError
import logging

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')

        user = AuthService.register_user(username, password, role)
        return jsonify({
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.role_name
        }), 201
    except Exception as e:
        logger.error(f"注册失败:{str(e)}", exc_info=True)
        raise InternalServerError("注册失败")

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = AuthService.authenticate_user(username, password)
        token = SecurityUtils.generate_jwt(user.user_id, user.role.role_name)
        return jsonify({
            "token": token,
            "expires_in": 3600
        }), 200
    except Exception as e:
        logger.error(f"登录失败:{str(e)}", exc_info=True)
        raise InternalServerError("登录失败")