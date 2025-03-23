"""用户认证路由"""
from flask import Blueprint, g, make_response, request, jsonify
from app.services.auth import AuthService
from app.utils.decorators import jwt_required, require_role
from app.utils.security import SecurityUtils
from app.utils.exceptions import Forbidden, InternalServerError, AppException
import logging

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        email = data.get("email")
        username = data.get("username")
        password = data.get("password")
        role = data.get("role", "user")
        code = data.get("code")

        user = AuthService.register_user(email, password, username, role, code)
        return jsonify({
            "message": "注册成功",
        }), 200
    except AppException as e:
        raise
    except Exception as e:
        logger.error(f"注册失败:{str(e)}", exc_info=True)
        raise InternalServerError("注册失败")

@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        user = AuthService.authenticate_user(email, password)
        token = SecurityUtils.generate_jwt(user.user_id, user.username, user.role)

        response = make_response(jsonify({"message": "登录成功"}))
        response.set_cookie(
            "jwt",
            token,
            domain="192.168.125.1",  # 匹配所有子域名
            httponly=True,
            secure=True,  # 开发环境关闭
            samesite="None",
            path="/"
        )
        return response, 200
    except AppException as e:
        raise
    except Exception as e:
        raise InternalServerError(f"登录失败:{e}")
    
@auth_bp.route("/logout", methods=["POST"])
def logout():
    response = make_response(jsonify({"message": "登出成功"}))
    # 通过设置过期时间清除cookie
    response.set_cookie("jwt", "", expires=0, httponly=True, secure=True, samesite="Strict")
    return response, 200

@auth_bp.route("/me", methods=["GET"])
@jwt_required
def get_current_user():
    user = g.current_user
    return jsonify({
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"]
    }), 200

@auth_bp.route("/check-session", methods=["GET"])
@jwt_required
def check_session():
    return jsonify({"status": "valid"}), 200

@auth_bp.route("/getcaptcha", methods=["POST"])
def getCaptcha():
    try:
        email = request.get_json().get("email")
        from app.services.auth import AuthService
        res = AuthService.sendCaptcha(email)
        return jsonify({
            "message": "验证码获取成功"
        }), 200
    except AppException as e:
        raise
    except Exception as e:
        raise InternalServerError(f"验证码获取失败{e}")

@auth_bp.route("/account", methods=["GET"])
@jwt_required
def get_account():
    try:
        user = AuthService.get_account(g.current_user["user_id"])
        return user.to_dict(), 200
    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"用户信息获取失败: {e}")

@auth_bp.route("/change-account", methods=["POST"])
@jwt_required
def change_account():
    try:
        data = request.get_json()
        user_id = g.current_user["user_id"]
        username = data.get("username")
        AuthService.change_account(user_id, username)
        return jsonify({
            "message": "修改成功"
        }), 200
    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"用户信息修改失败: {e}")

@auth_bp.route("/change-password", methods=["POST"])
@jwt_required
def change_password():
    try:
        data = request.get_json()
        user_id = g.current_user["user_id"]
        old_password = data.get("old_password")
        new_password = data.get("new_password")
        AuthService.change_password(user_id, old_password, new_password)
        return jsonify({
            "message": "密码修改成功"
        }), 200
    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"密码修改失败: {e}")
    
@auth_bp.route("/add-admin", methods=["POST"])
@jwt_required
@require_role("admin")
def admin_reg():
    try:
        data = request.get_json()
        email = data.get("email")
        username = data.get("username")
        password = data.get("password")
        role = data.get("role")
        AuthService.admin_reg(email, username, password, role)

        return jsonify({
            "message": f"用户{username}添加成功"
        }), 200

    except AppException: raise
    except Exception as e:
        raise InternalServerError(f"用户添加失败{str(e)}")

@auth_bp.route("/get-users", methods=["GET"])
@jwt_required
@require_role("admin")
def get_users():
    try:
        keyword = request.args.get("keyword", type=str)
        users = AuthService.get_all_user(keyword)
        return jsonify({
            "users": [{
                "user_id": u.user_id,
                "email": u.email,
                "username": u.username,
                "role": u.role,
                "created_at": u.created_at.isoformat()
            } for u in users]
        }), 200
    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"获取用户列表失败: {str(e)}")
    
@auth_bp.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required
@require_role("admin")
def delete_user(user_id):
    try:
        if user_id == 1:
            raise Forbidden("禁止删除默认帐号")
        AuthService.delete_user(user_id)
        return jsonify({"message": "用户删除成功"}), 200
    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"用户删除失败: {str(e)}")
    
@auth_bp.route("/admin-change-info", methods=["POST"])
@jwt_required
@require_role("admin")
def admin_change_info():
    try:
        data = request.get_json()
        user_id = data.get("user_id")
        if user_id == 1:
            raise Forbidden("禁止修改默认帐号")
        username = data.get("username")
        email = data.get("email")
        AuthService.change_account(user_id, username, email)
        return jsonify({
            "message": "修改成功"
        }), 200
    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"用户信息修改失败: {e}")

@auth_bp.route("/admin-restart-password/<int:user_id>", methods=["GET"])
@jwt_required
@require_role("admin")
def admin_start_password(user_id):
    try:
        if user_id == 1:
            raise Forbidden("禁止重置默认帐号密码，请查看系统日志查看默认密码")
        AuthService.restart_password(user_id)
        return jsonify({
            "message": "密码修改成功"
        }), 200
    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"密码修改失败: {e}")