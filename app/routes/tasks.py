'''扫描任务管理路由'''
from flask import Blueprint, request, jsonify
from app.services.task import TaskService
from app.utils.decorators import jwt_required, roles_required
from app.models.scan_task import ScanTask

tasks_bp = Blueprint('tasks', __name__)

@tasks_bp.route('', methods=['POST'])
@jwt_required
@roles_required('user', 'admin')
def create_task():
    try:
        data = request.get_json()
        user_id = request.current_user.user_id
        target_url = data.get('target_url')
        scan_type = data.get('scan_type', 'quick')

        task = TaskService.create_task(user_id, target_url, scan_type)
        return jsonify({
            "task_id": task.task_id,
            "status": task.status
        }), 202
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "任务创建失败"}), 500

@tasks_bp.route('', methods=['GET'])
@jwt_required
def get_tasks():
    try:
        user_id = request.current_user.user_id
        page = request.args.get('page', 1, type=int)
        size = request.args.get('size', 10, type=int)

        tasks = TaskService.get_user_tasks(user_id, page, size)
        return jsonify({
            "total": tasks.total,
            "tasks": [{
                "task_id": task.task_id,
                "target_url": task.target_url,
                "status": task.status
            } for task in tasks.items]
        }), 200
    except Exception as e:
        return jsonify({"error": "获取任务失败"}), 500

@tasks_bp.route('/<int:task_id>/start', methods=['POST'])
def start_scan(task_id):
    task = ScanTask.query.get_or_404(task_id)
    task.start_scan()
    return jsonify({"status": "scan started"}), 202