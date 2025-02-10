'''漏洞查询与报告路由'''
from flask import Blueprint, request, jsonify
from app.services.vul import VulService
from app.utils.decorators import jwt_required

vuls_bp = Blueprint('vuls', __name__)

@vuls_bp.route('/<int:task_id>/vuls', methods=['GET'])
@jwt_required
def get_vulnerabilities(task_id):
    try:
        severity_filter = request.args.get('severity')
        vuls = VulService.get_vulnerabilities(task_id, severity_filter)
        return jsonify({
            "vuls": [{
                "vul_id": vul.vul_id,
                "cve_id": vul.cve_id,
                "severity": vul.severity
            } for vul in vuls]
        }), 200
    except Exception as e:
        return jsonify({"error": "获取漏洞失败"}), 500

@vuls_bp.route('/reports', methods=['POST'])
@jwt_required
def generate_report():
    try:
        data = request.get_json()
        task_id = data.get('task_id')
        format = data.get('format', 'pdf')

        report_url = VulService.generate_report(task_id, format)
        return jsonify({"report_url": report_url}), 200
    except Exception as e:
        return jsonify({"error": "生成报告失败"}), 500