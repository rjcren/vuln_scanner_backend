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
        user_id = g.current_user['user_id']
        task_name = data.get('task_name')
        target_url = data.get('target_url')
        scan_type = data.get('scan_type', 'quick')

        if not ScannerUtils.validate_target(target_url):
            raise BadRequest("无效url")

        task = TaskService.create_task(user_id, task_name, target_url, scan_type)
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

@tasks_bp.route('/gettasks', methods=['GET'])
@jwt_required
def get_tasks():
    try:
        user_id = g.current_user['user_id']
        role = g.current_user['role']
        page = request.args.get('page', 1, type=int)
        size = request.args.get('size', 10, type=int)
        keyword = request.args.get('keyword', type=str)
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


@tasks_bp.route('/delete', methods=['POST'])
@jwt_required
def delete_tasks():
    """删除任务"""
    try:
        task_ids = request.get_json().get('task_id')
        print(task_ids)
        if not task_ids:
            raise BadRequest("缺少要删除的任务ID")

        TaskService.delete_task(task_ids.split(','))
        return jsonify({"message": "删除成功"}), 204

    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"删除任务失败: {e}")

@tasks_bp.route('/<int:task_id>/start', methods=['POST'])
def start_scan(task_id):
    task = ScanTask.query.get_or_404(task_id)
    task.start_scan()
    return jsonify({"status": "scan started"}), 202