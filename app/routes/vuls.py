"""漏洞查询与报告路由"""
from flask import Blueprint, request, jsonify
from app.services.vul import VulService
from app.utils.decorators import jwt_required, require_role
from app.utils.exceptions import AppException, InternalServerError
from sqlalchemy import func
from datetime import datetime, timedelta

vuls_bp = Blueprint("vuls", __name__)

@vuls_bp.route("/vul-list", methods=["GET"])
@jwt_required
def get_vuls():
    """获取漏洞列表"""
    try:
        # 获取分页参数
        page = request.args.get('page', 1)
        size = request.args.get('size', 10)
        keyword = request.args.get('keyword')
        
        # 获取过滤参数
        task_id = request.args.get('task_id')
        severity = request.args.get('severity')
        scan_source = request.args.get('scan_source')
        
        # 获取分页后的漏洞数据
        pagination = VulService.get_vuls(task_id, severity, scan_source, int(page), int(size), keyword)
        
        # 构造返回数据
        return jsonify({
            "data": [{
                "vul_id": vul.vul_id,
                "task_id": vul.task_id,
                "scan_source": vul.scan_source,
                "scan_id": vul.scan_id,
                "vul_type": vul.vul_type,
                "severity": vul.severity,
                "description": vul.description,
                "solution": vul.solution,
                "time": vul.time,
                "task_name": vul.task.task_name if vul.task else "未知任务",
                "target_url": vul.task.target_url if vul.task else "未知URL"
            } for vul in pagination.items],
            "total": pagination.total,
            "page": pagination.page,
            "pages": pagination.pages,
            "per_page": pagination.per_page
        }), 200
    except AppException:
        raise
    except Exception as e:
        raise InternalServerError(f"获取漏洞列表错误: {str(e)}")

@vuls_bp.route("/severity-stats", methods=["GET"])
@jwt_required
def get_severity_stats():
    """获取漏洞严重程度统计"""
    try:
        status = VulService.get_severity_stats()
        return jsonify({severity: count for severity, count in status} if status else None), 200
    except Exception as e:
        raise InternalServerError(f"获取漏洞统计失败: {str(e)}")

@vuls_bp.route("/latest-alerts", methods=["GET"])
@jwt_required
def get_latest_alerts():
    """获取最新漏洞告警"""
    try:
        alerts = VulService.get_latest_alerts()
        return jsonify(alerts), 200
    except Exception as e:
        raise InternalServerError(f"获取最新告警失败: {str(e)}")

@vuls_bp.route("/high-risk-count", methods=["GET"])
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