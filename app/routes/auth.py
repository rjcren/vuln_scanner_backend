'''用户认证路由'''
from flask import Blueprint, request, jsonify
from app.services.auth import AuthService
from app.utils.security import SecurityUtils
from app.utils.exceptions import Unauthorized, AppException

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
    except AppException as e:
        return jsonify({"error": str(e)}), 409
    except Exception as e:
        return jsonify({"error": "内部服务器错误"}), 500

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
    except Unauthorized as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        return jsonify({"error": "登录失败"}), 500