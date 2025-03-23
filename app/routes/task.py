"""扫描任务管理路由"""
from flask import Blueprint, g, request, jsonify
from app.models.task_log import TaskLog
from app.services.task import TaskService
from app.utils.decorators import jwt_required
from app.utils.exceptions import AppException, BadRequest, Forbidden, InternalServerError, ValidationError
from app.utils.validation import InputValidator

tasks_bp = Blueprint("tasks", __name__)

@tasks_bp.route("/createtask", methods=["POST"])
@jwt_required
def create_task():
    data = request.get_json()
    user_id = g.current_user["user_id"]
    task_name = data.get("task_name")
    target_url = data.get("target_url")
    scan_type = data.get("scan_type", "quick")
    try:
        if not InputValidator.validate_url(target_url):
            raise ValidationError("无效url")

        task = TaskService.create_task(user_id, task_name, target_url, scan_type)
        if task:
            TaskLog.add_log(task.task_id, "INFO", "创建任务成功")
            return jsonify({
                "task_id": task.task_id,
                "status": task.status
            }), 202
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except AppException as e:
        raise
    except Exception as e:
        raise InternalServerError(f"任务创建失败:{e}")

@tasks_bp.route("/gettasks", methods=["GET"])
@jwt_required
def get_tasks():
    try:
        user_id = g.current_user["user_id"]
        role = g.current_user["role"]
        page = request.args.get("page", 1, type=int)
        size = request.args.get("size", 10, type=int)
        keyword = request.args.get("keyword", type=str)
        tasks = TaskService.get_tasks(role, user_id, page, size, keyword)
        return jsonify({
            "total": tasks.total,
            "tasks": [{
                "task_id": task.task_id,
                "task_name": task.task_name,
                "username": task.user.username,
                "target_url": task.target_url,
                "scan_type": task.scan_type,
                "status": task.status,
                "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "finished_at": task.finished_at.strftime("%Y-%m-%d %H:%M:%S") if task.finished_at else None
            } for task in tasks.items]
        }), 202
    except AppException:
        raise
    except Exception as e:
        return InternalServerError(f"获取任务列表失败:{e}")


@tasks_bp.route("/delete", methods=["POST"])
@jwt_required
def delete_tasks():
    """删除任务"""
    try:
        task_ids = request.get_json().get("task_id")
        if not task_ids:
            raise BadRequest("缺少要删除的任务ID")

        role = g.current_user["role"]
        user_id = g.current_user["user_id"]
        count = TaskService.delete_task(task_ids.split(","), role, user_id)
        return jsonify({"message": f"删除成功: {count}个任务"}), 200

    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"删除任务失败: {e}")

@tasks_bp.route("/<int:task_id>", methods=["GET"])
@jwt_required
def get_task(task_id):
    try:
        task = TaskService.get_task(task_id)
        return jsonify({
            "task_id": task.task_id,
            "task_name": task.task_name,
            "target_url": task.target_url,
            "scan_type": task.scan_type,
            "status": task.status,
            "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "finished_at": task.finished_at.strftime("%Y-%m-%d %H:%M:%S") if task.finished_at else None,
            "task_logs": [log.to_dict() for log in task.task_logs] if task.task_logs else [],
            "vulnerabilities": [vuln.to_dict() for vuln in task.vulnerabilities] if task.vulnerabilities else [],
            "risk_reports": [report.to_dict() for report in task.risk_reports] if task.risk_reports else [],
        }), 202
    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"获取任务详情失败: {e}")
    
@tasks_bp.route("/running-count", methods=["GET"])
@jwt_required
def get_running_count():
    """获取运行中的任务数量"""
    try:
        count = TaskService.get_running_count()
        return jsonify({
            "count": count if count else 0
        }), 200
    except Exception as e:
        raise InternalServerError(f"获取运行中任务数量失败: {str(e)}")

@tasks_bp.route("/status-stats", methods=["GET"])
@jwt_required 
def get_status_stats():
    """获取任务状态统计"""
    try:
        status = TaskService.get_task_status_stats()
        return jsonify({key: count for key, count in status} if status else None), 200
    except Exception as e:
        raise InternalServerError(f"获取任务状态统计失败: {str(e)}")

@tasks_bp.route("/start", methods=["POST"])
@jwt_required
def start_scan():
    try:
        task_id = request.get_json().get("task_id")
        TaskService.start_scan_task(task_id)

        return jsonify({"message": "扫描任务已启动"}), 202
    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"启动扫描失败: {e}")
    

@tasks_bp.route("/reports", methods=["POST"])
@jwt_required
def generate_report():
    try:
        data = request.get_json()
        task_id = data.get("task_id")
        format = data.get("format", "pdf")

        report_url = TaskService.generate_report(task_id, format)
        return jsonify({"report_url": report_url}), 200
    except AppException as e:
        raise
    except Exception as e:
        return InternalServerError(f"生成报告失败: {str(e)}")
