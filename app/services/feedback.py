"""用户反馈服务"""
from flask import g
from flask_mail import Message
from app.models import UserFeedback
from app.extensions import db, mail
from app.utils.exceptions import ValidationError

class FeedbackService:
    @staticmethod
    def submit_feedback(user_id: int, task_id: int, description: str) -> UserFeedback:
        feedback = UserFeedback(
            user_id=user_id,
            task_id=task_id,
            description=description
        )
        db.session.add(feedback)
        db.session.commit()
        return feedback
    
    @staticmethod
    def get_all_feedback() -> list:
        """获取所有反馈列表"""
        return UserFeedback.query.all()

    @staticmethod
    def update_feedback_status(feedback_id: int, status: str) -> UserFeedback:
        """修改指定反馈的状态"""
        if status not in ["pending", "resolved", "rejected"]:
            raise ValidationError("无效的反馈状态")
        feedback = UserFeedback.query.get(feedback_id)
        if not feedback:
            raise ValidationError("反馈不存在")
        feedback.status = status
        db.session.commit()
        return feedback

    @staticmethod
    def delete_feedback(feedback_id: int) -> None:
        """删除指定的反馈"""
        feedback = UserFeedback.query.get(feedback_id)
        if not feedback:
            raise ValidationError("反馈不存在")
        db.session.delete(feedback)
        db.session.commit()

    @staticmethod
    def send_receipt(feedback_id: int, msg) -> None:
        """发送反馈确认邮件"""
        feedback = UserFeedback.query.get(feedback_id)
        if not feedback:
            raise ValidationError("反馈不存在")
        email = feedback.user.email
        message = Message(subject="漏洞检测系统反馈回执", recipients=[email], body=f"您的反馈已被管理员{g.current_user["username"]}处理，反馈回执如下：\n{msg}")
        mail.send(message)
        feedback.receipt = f"{feedback.receipt}\n{g.current_user["username"]}回复{msg}"
        db.session.commit()