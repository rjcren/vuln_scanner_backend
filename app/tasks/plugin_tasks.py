'''插件执行任务'''
from celery import shared_task
from app.models import Plugin, ScanTask
from app.extensions import db
from app.utils.scanner import execute_custom_plugin
from app.utils.logger import setup_logger

logger = setup_logger(__name__)

@shared_task(name="run_plugin_task")
def run_plugin_task(plugin_id: int, task_id: int):
    """执行自定义插件扫描"""
    try:
        plugin = db.session.get(Plugin, plugin_id)
        task = db.session.get(ScanTask, task_id)
        if not plugin or not task:
            logger.error("插件或任务不存在")
            return

        # 执行插件逻辑
        result = execute_custom_plugin(plugin.file_path, task.target_url)

        # 处理结果（示例）
        if result.get("vulnerabilities"):
            ScannerService.save_vulnerabilities(task_id, result["vulnerabilities"])

        logger.info(f"插件 {plugin.name} 执行成功")
    except Exception as e:
        logger.error(f"插件执行失败: {str(e)}")
        raise