'''定时任务'''
from celery.schedules import crontab
from app.extensions import celery
from app.models import ThreatIntel
from app.services.threat_intel import ThreatIntelService
from app.utils.logger import setup_logger

logger = setup_logger(__name__)

@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """注册定时任务"""
    # 每天凌晨3点同步威胁情报
    sender.add_periodic_task(
        crontab(hour=3, minute=0),
        sync_threat_intel_task.s(),
        name="daily_threat_intel_sync"
    )

@celery.task(name="sync_threat_intel_task")
def sync_threat_intel_task():
    """同步CVE/NVD漏洞数据库"""
    try:
        new_records = ThreatIntelService.sync_from_cve()
        logger.info(f"成功同步 {len(new_records)} 条威胁情报")
    except Exception as e:
        logger.error(f"威胁情报同步失败: {str(e)}")
        raise