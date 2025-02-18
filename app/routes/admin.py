'''管理员用户/角色管理路由'''
from flask import Blueprint, request, jsonify
from app.services.admin import AdminService
from app.utils.decorators import jwt_required, roles_required

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@jwt_required
@roles_required('admin')
def update_user_role(user_id):
    try:
        data = request.get_json()
        new_role = data.get('role')

        user = AdminService.update_user_role(user_id, new_role)
        return jsonify({
            "user_id": user.user_id,
            "new_role": user.role.role_name
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "角色更新失败"}), 500