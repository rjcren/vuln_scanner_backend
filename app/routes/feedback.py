'''用户反馈路由'''
from flask import Blueprint, request, jsonify
from app.services.feedback import FeedbackService
from app.utils.decorators import jwt_required

feedback_bp = Blueprint('feedback', __name__)

@feedback_bp.route('', methods=['POST'])
@jwt_required
def submit_feedback():
    try:
        data = request.get_json()
        user_id = request.current_user.user_id
        task_id = data.get('task_id')
        description = data.get('description')

        feedback = FeedbackService.submit_feedback(user_id, task_id, description)
        return jsonify({
            "feedback_id": feedback.feedback_id,
            "status": feedback.status
        }), 201
    except Exception as e:
        return jsonify({"error": "提交反馈失败"}), 500