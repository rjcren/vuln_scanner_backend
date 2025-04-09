"""用户反馈路由"""
from flask import Blueprint, g, request, jsonify
from app.services.feedback import FeedbackService
from app.utils.decorators import api_key_required, jwt_required, require_role
from app.utils.exceptions import InternalServerError, ValidationError, AppException
import logging

logger = logging.getLogger(__name__)
feedback_bp = Blueprint("feedback", __name__)

@feedback_bp.route("", methods=["POST"])
@api_key_required
@jwt_required
def submit_feedback():
    try:
        data = request.get_json()
        if not data or "task_id" not in data or "description" not in data:
            logger.error("缺少必要参数", exc_info=True)
            raise ValidationError("缺少必要参数")
        user_id = g.current_user["user_id"]
        task_id = data.get("task_id")
        description = data.get("description")

        feedback = FeedbackService.submit_feedback(user_id, task_id, description)
        return jsonify({
            "feedback_id": feedback.feedback_id,
            "status": feedback.status
        }), 201
    except AppException as e:
        raise
    except Exception as e:
        raise InternalServerError(f"提交反馈失败: {str(e)}")
    
@feedback_bp.route("", methods=["GET"])
@api_key_required
@jwt_required
@require_role("admin")
def get_all_feedback():
    """获取所有用户反馈列表"""
    try:
        feedbacks = FeedbackService.get_all_feedback()
        data = []
        for fb in feedbacks:
            data.append({
                "feedback_id": fb.feedback_id,
                "username": fb.user.username if fb.user else None,
                "task_name": fb.task.task_name if fb.task else None,
                "description": fb.description,
                "status": fb.status,
                "created_at": fb.created_at.isoformat() if fb.created_at else None
            })
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"获取反馈列表失败: {e}", exc_info=True)
        raise InternalServerError("获取反馈列表失败")

@feedback_bp.route("/<int:feedback_id>", methods=["PATCH"])
@api_key_required
@jwt_required
@require_role("admin")
def update_feedback(feedback_id: int):
    """修改用户反馈状态"""
    try:
        data = request.get_json()
        if not data or "status" not in data:
            logger.error("缺少必要参数", exc_info=True)
            raise ValidationError("缺少必要参数")
        new_status = data.get("status")
        feedback = FeedbackService.update_feedback_status(feedback_id, new_status)
        return jsonify({
            "feedback_id": feedback.feedback_id,
            "status": feedback.status
        }), 200
    except AppException as e:
        raise
    except Exception as e:
        logger.error(f"更新反馈状态失败: {e}", exc_info=True)
        raise InternalServerError("更新反馈状态失败")

@feedback_bp.route("/<int:feedback_id>", methods=["DELETE"])
@api_key_required
@jwt_required
@require_role("admin")
def delete_feedback(feedback_id: int):
    """删除用户反馈"""
    try:
        FeedbackService.delete_feedback(feedback_id)
        return jsonify({"message": "反馈已删除"}), 200
    except AppException as e:
        raise
    except Exception as e:
        logger.error(f"删除反馈失败: {e}", exc_info=True)
        raise InternalServerError("删除反馈失败")