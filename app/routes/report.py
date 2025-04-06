from flask import Blueprint, jsonify, request, send_file

from app.services.report import ReportService
from app.utils.decorators import api_key_required, jwt_required
from app.utils.exceptions import AppException, InternalServerError


report_bp = Blueprint("reports", __name__)


@report_bp.route("/report", methods=["POST"])
@api_key_required
@jwt_required
def generate_report():
    try:
        data = request.get_json()
        task_id = data.get("task_id")
        report_type = data.get("format", "pdf")

        report_path = ReportService().generate_report(task_id, report_type)
        return send_file(report_path, as_attachment=True)
    except AppException as e:
        raise
    except Exception as e:
        return InternalServerError(f"生成报告失败: {str(e)}")


@report_bp.route("/reports", methods=["GET"])
@api_key_required
@jwt_required
def get_reports():
    try:
        reports = ReportService().get_reports()
        return (
            jsonify(
                {
                    "data": [
                        {
                            "report_id": report.report_id,
                            "task_id": report.task_id,
                            "task_name": report.task.task_name,
                            "url": report.task.target_url,
                            "type": report.type,
                            "created_at": report.generated_at.strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                        }
                        for report in reports
                    ]
                }
            ),
            200,
        )
    except AppException as e:
        raise
    except Exception as e:
        return InternalServerError(f"获取报告失败: {str(e)}")


@report_bp.route("/report/<int:task_id>", methods=["GET"])
@api_key_required
@jwt_required
def get_report(task_id):
    try:
        report_path = ReportService().get_report(task_id)
        return send_file(report_path, as_attachment=True)
    except AppException as e:
        raise
    except Exception as e:
        return InternalServerError(f"获取报告失败: {str(e)}")


@report_bp.route("/report/<int:report_id>", methods=["DELETE"])
@api_key_required
@jwt_required
def delete_report(report_id):
    try:
        ReportService().delete_report(report_id)
        return jsonify({"message": "删除成功"}), 200
    except AppException as e:
        raise
    except Exception as e:
        return InternalServerError(f"删除报告失败: {str(e)}")
