'''扫描任务管理路由'''
from flask import Blueprint, g, request, jsonify
from app.services.task import TaskService
from app.utils.decorators import jwt_required
from app.models.scan_task import ScanTask
from app.utils.exceptions import AppException, BadRequest, InternalServerError
from app.utils.scanner import ScannerUtils

tasks_bp = Blueprint('tasks', __name__)

@tasks_bp.route('/createtask', methods=['POST'])
@jwt_required
def create_task():
    try:
        data = request.get_json()
        user_id = g.current_user.user_id
        target_url = data.get('target_url')
        scan_type = data.get('scan_type', 'quick')

        if not ScannerUtils.validate_target(target_url):
            raise BadRequest("无效url")

        task = TaskService.create_task(user_id, target_url, scan_type)
        return jsonify({
            "task_id": task.task_id,
            "status": task.status
        }), 202
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except AppException as e:
        raise
    except Exception as e:
        raise InternalServerError("任务创建失败")

@tasks_bp.route('/gettasks', methods=['GET'])
@jwt_required
def get_tasks():
    try:
        user_id = g.current_user['user_id']
        role = g.current_user['role']
        page = request.args.get('page', 1, type=int)
        size = request.args.get('size', 10, type=int)
        tasks = TaskService.get_tasks(role, user_id, page, size)
        return jsonify({
            "total": tasks.total,
            "tasks": [{
                "task_id": task.task_id,
                "target_url": task.target_url,
                "status": task.status,
                "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "finished_at": task.finished_at.strftime("%Y-%m-%d %H:%M:%S") if task.finished_at else None
            } for task in tasks.items]
        }), 202
    except AppException as e:
        raise
    except Exception as e:
        return InternalServerError(f"获取任务列表失败:{e}")

@tasks_bp.route('/<int:task_id>/start', methods=['POST'])
def start_scan(task_id):
    task = ScanTask.query.get_or_404(task_id)
    task.start_scan()
    return jsonify({"status": "scan started"}), 202