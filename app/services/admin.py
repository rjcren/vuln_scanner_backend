from typing import List, Dict, Optional
from app.extensions import db
from app.models import User, Role
from app.utils.exceptions import (
    UserAlreadyExists, NotFound, Forbidden,
    Conflict, BadRequest, InternalServerError
)
from app.utils.decorators import roles_required
from flask import abort
import logging

logger = logging.getLogger(__name__)

class AdminService:
    """后台管理服务类（异常处理优化版）"""

    # ========================
    # 用户管理功能
    # ========================

    @staticmethod
    @roles_required('admin')
    def create_user(user_data: Dict) -> User:
        """创建新用户（返回201状态码需在控制器层处理）"""
        try:
            # 用户名冲突检查
            if User.query.filter_by(username=user_data['username']).first():
                abort(Conflict(f"用户已被注册"))

            # 角色有效性验证
            role_id = user_data.get('role_id', 2)
            if not Role.query.get(role_id):
                abort(BadRequest("无效的角色ID"))

            # 创建用户
            new_user = User(
                username=user_data['username'],
                password=user_data['password'],  # 实际应使用密码哈希
                email=user_data.get('email'),
                role_id=role_id
            )

            db.session.add(new_user)
            db.session.commit()
            return new_user

        except Exception as e:
            db.session.rollback()
            logger.error(f"创建用户失败: {str(e)}", exc_info=True)
            abort(InternalServerError(f"创建用户失败"))

    @staticmethod
    @roles_required('admin')
    def delete_user(user_id: int) -> None:
        """删除用户"""
        user = User.query.get(user_id)
        if not user:
            abort(NotFound(f"用户 {user.username} 不存在"))

        if user.role.role_name == 'admin':
            abort(Forbidden("不能删除管理员账户"))

        try:
            db.session.delete(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"删除用户失败: {str(e)}", exc_info=True)
            abort(InternalServerError(f"删除用户失败"))

    @staticmethod
    @roles_required('admin')
    def update_user(user_id: int, update_data: Dict) -> User:
        """更新用户信息"""
        user = User.query.get(user_id)
        if not user:
            abort(NotFound("角色不存在"))

        try:
            # 用户名更新检查
            if 'username' in update_data:
                existing_user = User.query.filter(
                    User.id != user_id,
                    User.username == update_data['username']
                ).first()
                if existing_user:
                    abort(Conflict("用户名已被占用"))

                user.username = update_data['username']

            # 密码更新
            if 'password' in update_data:
                user.set_password(update_data['password'])

            # 角色更新验证
            if 'role_id' in update_data:
                role = Role.query.get(update_data['role_id'])
                if not role:
                    abort(BadRequest("无效的角色ID"))
                user.role_id = update_data['role_id']

            db.session.commit()
            return user

        except Exception as e:
            db.session.rollback()
            logger.error(f": {str(e)}", exc_info=True)
            abort(InternalServerError("更新用户失败"))

    @staticmethod
    def list_users(page: int = 1, per_page: int = 10) -> Dict:
        """分页获取用户列表"""
        try:
            pagination = User.query.paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )

            return {
                "items": [user.to_dict() for user in pagination.items],
                "total": pagination.total,
                "pages": pagination.pages,
                "current_page": pagination.page
            }
        except Exception as e:
            logger.error(f"获取用户列表失败: {str(e)}", exc_info=True)
            abort(InternalServerError("获取用户列表失败"))

    # ========================
    # 角色管理功能
    # ========================

    @staticmethod
    @roles_required('admin')
    def create_role(role_data: Dict) -> Role:
        """创建新角色"""
        if Role.query.filter_by(role_name=role_data['role_name']).first():
            abort(Conflict("角色名称已存在"))

        try:
            new_role = Role(
                role_name=role_data['role_name'],
                permissions=role_data.get('permissions', [])
            )
            db.session.add(new_role)
            db.session.commit()
            return new_role
        except Exception as e:
            db.session.rollback()
            logger.error(f"创建角色失败: {str(e)}", exc_info=True)
            abort(InternalServerError("创建角色失败"))

    @staticmethod
    @roles_required('admin')
    def update_role(role_id: int, update_data: Dict) -> Role:
        """更新角色信息"""
        role = Role.query.get(role_id)
        if not role:
            abort(NotFound("角色不存在"))

        if role.role_name == 'admin':
            abort(Forbidden("角色为管理员"))

        try:
            # 角色名称冲突检查
            if 'role_name' in update_data:
                existing_role = Role.query.filter(
                    Role.id != role_id,
                    Role.role_name == update_data['role_name']
                ).first()
                if existing_role:
                    abort(Conflict("角色名称已存在"))

                role.role_name = update_data['role_name']

            # 权限更新
            if 'permissions' in update_data:
                role.permissions = update_data['permissions']

            db.session.commit()
            return role

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新角色失败: {str(e)}", exc_info=True)
            abort(InternalServerError("更新角色失败"))

    @staticmethod
    @roles_required('admin')
    def delete_role(role_id: int) -> None:
        """删除角色"""
        role = Role.query.get(role_id)
        if not role:
            abort(NotFound("角色不存在"))

        if role.role_name == 'admin':
            abort(Forbidden("不能删除管理员"))

        if User.query.filter_by(role_id=role_id).first():
            abort(BadRequest("该角色仍有用户关联"))  # 400

        try:
            db.session.delete(role)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"删除角色失败: {str(e)}", exc_info=True)
            abort(InternalServerError("删除角色失败"))

    @staticmethod
    def list_roles() -> List[Dict]:
        """获取所有角色列表"""
        try:
            return [{
                "id": role.id,
                "name": role.role_name,
                "permissions": role.permissions
            } for role in Role.query.all()]
        except Exception as e:
            logger.error(f"获取角色列表失败: {str(e)}", exc_info=True)
            abort(InternalServerError("获取角色列表失败"))