"""扫描服务 - 负责业务流程编排和状态管理"""
from typing import List
from app.extensions import db
from app.models import ScanTask, Vulnerability
from app.utils.scanner import ScannerUtils
import logging

logger = logging.getLogger(__name__)

class ScanService:
    """扫描任务服务"""

    @staticmethod
    def execute_task(task_id: int):
        """执行完整扫描流程"""
        task = ScanTask.query.get(task_id)
        if not task:
            logger.error(f"扫描任务 {task_id} 不存在")
            return

        try:
            task.status = "running"
            db.session.commit()

            # 执行核心扫描
            scan_results = []
            scan_results += ScannerUtils.run_nmap(task.target_url)

            if task.scan_type == "web":
                scan_results += ScannerUtils.run_zap(task.target_url)

            # 保存结果
            ScanService._save_results(task.id, scan_results)

            task.status = "completed"
        except Exception as e:
            task.status = "failed"
            logger.exception(f"扫描任务 {task_id} 执行异常: {str(e)}")
        finally:
            db.session.commit()

    @staticmethod
    def _save_results(task_id: int, results: List[Vulnerability]):
        """保存漏洞结果到数据库"""
        for item in results:
            vuln = Vulnerability(
                task_id=task_id,
                vul_type=item["type"],
                severity=item["severity"],
                description=item["description"]
            )
            db.session.add(vuln)
        db.session.commit()