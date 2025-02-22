'''管理员用户/角色管理路由'''
from flask import Blueprint, request, jsonify
from app.services.admin import AdminService
from app.utils.decorators import jwt_required, roles_required
from app.utils.exceptions import InternalServerError, BadRequest
import logging

logger = logging.getLogger(__name__)
admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@jwt_required
@roles_required('admin')
def update_user_role(user_id):
    try:
        data = request.get_json()
        new_role = data.get('role')
        if not new_role or not isinstance(new_role, str):
            raise BadRequest("参数为空")

        user = AdminService.update_user_role(user_id, new_role)
        return jsonify({
            "user_id": user.user_id,
            "new_role": user.role.role_name
        }), 200
    except Exception as e:
        logger.error(f"更新用户{user_id}角色失败: {e}")
        return InternalServerError({"角色更新失败"})