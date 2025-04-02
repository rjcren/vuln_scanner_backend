"""用户反馈路由"""
from flask import Blueprint, g, request, jsonify
from app.services.feedback import FeedbackService
from app.utils.decorators import jwt_required
from app.utils.exceptions import InternalServerError, ValidationError, AppException
import logging

logger = logging.getLogger(__name__)
feedback_bp = Blueprint("feedback", __name__)

@feedback_bp.route("", methods=["POST"])
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
        logger.error(f"提交反馈失败: {e}", exc_info=True)
        raise InternalServerError({"提交反馈失败"})