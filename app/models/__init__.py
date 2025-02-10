from .user import User
from .role import Role
from .permission import Permission
from .scan_task import ScanTask
from .vulnerability import Vulnerability
from .task_log import TaskLog
from .fuzz_result import FuzzResult
from .user_feedback import UserFeedback
from .risk_report import RiskReport
from .threat_intel import ThreatIntel

# 显式声明可导出的模型类
__all__ = [
    "User",
    "Role",
    "Permission",
    "ScanTask",
    "Vulnerability",
    "TaskLog",
    "FuzzResult",
    "UserFeedback",
    "RiskReport",
    "ThreatIntel",
]