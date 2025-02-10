'''插件管理路由'''
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from app.services.plugin import PluginService
from app.utils.decorators import jwt_required, roles_required('admin')

plugins_bp = Blueprint('plugins', __name__)

@plugins_bp.route('', methods=['POST'])
@jwt_required
@roles_required('admin')
def upload_plugin():
    try:
        file = request.files['file']
        if not file:
            return jsonify({"error": "未上传文件"}), 400

        filename = secure_filename(file.filename)
        plugin = PluginService.upload_plugin(file, filename)
        return jsonify({
            "plugin_id": plugin.plugin_id,
            "name": plugin.name,
            "status": plugin.status
        }), 201
    except Exception as e:
        return jsonify({"error": "插件上传失败"}), 500