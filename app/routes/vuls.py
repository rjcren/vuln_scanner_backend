'''漏洞查询与报告路由'''
from flask import Blueprint, request, jsonify
from app.services.vul import VulService
from app.utils.decorators import jwt_required, require_role
from app.utils.exceptions import AppException, InternalServerError

vuls_bp = Blueprint('vuls', __name__)

@vuls_bp.route('/vul-list', methods=['PUT'])
@jwt_required
def get_vul():
    try:
        VulService.get_vuls()


    except Exception as e:
        raise InternalServerError(f"获取漏洞详情错误: {str(e)}")

@vuls_bp.route('/reports', methods=['POST'])
@jwt_required
def generate_report():
    try:
        data = request.get_json()
        task_id = data.get('task_id')
        format = data.get('format', 'pdf')

        report_url = VulService.generate_report(task_id, format)
        return jsonify({"report_url": report_url}), 200
    except AppException as e:
        raise
    except Exception as e:
        return jsonify({"error": "生成报告失败"}), 500