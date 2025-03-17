'''漏洞查询与报告路由'''
from flask import Blueprint, request, jsonify
from app.services.vul import VulService
from app.utils.decorators import jwt_required, require_role
from app.utils.exceptions import AppException, InternalServerError
from sqlalchemy import func
from datetime import datetime, timedelta

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

@vuls_bp.route('/severity-stats', methods=['GET'])
@jwt_required
def get_severity_stats():
    """获取漏洞严重程度统计"""
    try:
        status = VulService.get_severity_stats()
        return jsonify({severity: count for severity, count in status} if status else None), 200
    except Exception as e:
        raise InternalServerError(f"获取漏洞统计失败: {str(e)}")

@vuls_bp.route('/latest-alerts', methods=['GET'])
@jwt_required
def get_latest_alerts():
    """获取最新漏洞告警"""
    try:
        alerts = VulService.get_latest_alerts()
        return jsonify(alerts), 200
    except Exception as e:
        raise InternalServerError(f"获取最新告警失败: {str(e)}")

@vuls_bp.route('/high-risk-count', methods=['GET'])
@jwt_required
def get_high_risk_count():
    """获取高风险漏洞数量"""
    try:
        count = VulService.get_high_risk_count()
        return jsonify({
            "count": count if count else 0
        }), 200
    except Exception as e:
        raise InternalServerError(f"获取高风险漏洞数量失败: {str(e)}")