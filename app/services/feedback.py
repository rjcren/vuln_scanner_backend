"""用户反馈服务"""
from app.models import UserFeedback
from app.extensions import db

class FeedbackService:
    @staticmethod
    def submit_feedback(user_id: int, task_id: int, description: str) -> UserFeedback:
        feedback = UserFeedback(
            user_id=user_id,
            task_id=task_id,
            vul_description=description
        )
        db.session.add(feedback)
        db.session.commit()
        return feedback