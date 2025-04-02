from datetime import datetime
import logging
import os
import time
from flask import current_app
import requests
from zapv2 import ZAPv2
from app.models.task_log import TaskLog
from app.models.vulnerability import Vulnerability
from app.services.vul import VulService
from app.utils.exceptions import InternalServerError, ValidationError

logger = logging.getLogger(__name__)


class ZAP:
    def __init__(self):
        # ZAP配置
        self.ZAP_API_KEY = os.getenv("ZAP_API_KEY", "your_api_key")
        self._ZAP_PROXY = {
            "http": current_app.config["ZAP_API_URL"],
            "https": current_app.config["ZAP_API_URL"],
        }
        self.zap = ZAPv2(
            apikey=self.ZAP_API_KEY, proxies=self._ZAP_PROXY, validate_status_code=False
        )

    def start_scan(self, task_id: int, target_url: str, scan_type: str = "full", login_url: str = None, username: str = None, password: str = None):
        """启动主动扫描"""
        SCAN_POLICIES = {
            "full": "all",
            "sql": {
                "scanners": [40018, 40019, 40020, 40021, 40022, 40027],
                "attack_strength": "HIGH",
                "alert_threshold": "HIGH"
            },
            "xss": {
                "scanners": [40012, 40014, 40026],
                "dependencies": [40017],
                "alert_threshold": "HIGH"
            },
            "weak_pass": None,
            "quick": None
        }

        policy_config = SCAN_POLICIES.get(scan_type)
        if not policy_config:
            raise ValueError(f"无效扫描类型: {scan_type}")
        
        try:
            context_name = "Default Context"
            context_id = self.zap.context.new_context(context_name)
            self.zap.context.include_in_context("Default Context", f".*{target_url.replace('.', r'\\.').replace(':', r'\\:')}.*")
            self.zap.context.set_context_in_scope("Default Context", True)
            if login_url and username and password:
                auth_method_config = f"loginUrl={login_url}&usernameParam={username}&passwordParam={password}"
                self.zap.authentication.set_authentication_method(
                    context_id,
                    "formBasedAuthentication", 
                    auth_method_config
                )
                self.zap.users.new_user(context_id, "auth_user")
                self.zap.forcedUser.set_forced_user(context_id, 0)  # 用户ID 0
                self.zap.forcedUser.set_forced_user_mode_enabled(True)
        except Exception as e:
            logger.error(f"ZAP添加自动登录失败: {str(e)}")
            TaskLog.add_log(task_id, "ERROR", f"ZAP添加自动登录失败")
            return None

        try:
            # 配置扫描策略
            if scan_type == "full":
                self.zap.ascan.enable_all_scanners()
                self.zap.ascan.set_policy_attack_strength("Default Policy", "HIGH")
            elif not policy_config: 
                TaskLog.add_log(task_id, "INFO", f"该扫描类型不启用ZAP")
                return
            else:
                # 专项扫描：启用指定扫描器
                scanners = policy_config.get("scanners", [])
                dependencies = policy_config.get("dependencies", [])
                # 启用依赖扫描器
                for sid in dependencies:
                    self.zap.ascan.enable_scanner(sid)
                # 启用主扫描器
                for sid in scanners:
                    self.zap.ascan.enable_scanner(sid)
                    if "attack_strength" in policy_config:
                        self.zap.ascan.set_scanner_attack_strength(
                            sid, 
                            policy_config["attack_strength"]
                        )
                    self.zap.ascan.set_scanner_alert_threshold(
                        sid, 
                        policy_config["alert_threshold"]
                    )
            # 启动扫描
            scan_id = self.zap.ascan.scan(target_url, recurse=True, inscopeonly=False)
            if scan_id.isdigit():
                TaskLog.add_log(task_id, "INFO", f"ZAP扫描已启动")
                return scan_id
            else: 
                TaskLog.add_log(task_id, "ERROR", f"ZAP扫描启动失败{scan_id}")
                return None
        except Exception as e:
            logger.error(f"ZAP扫描启动失败: {str(e)}")
            TaskLog.add_log(task_id, "ERROR", f"ZAP扫描启动失败")
            return None

    def stop_scan(self, scan_id: str):
        """停止ZAP扫描任务"""
        try:
            result = self.zap.ascan.stop(scan_id)
            if result != "OK":
                logger.error(f"停止ZAP扫描失败: {result}")
                return False
        except Exception as e:
            logger.error(f"停止ZAP扫描异常: {str(e)}")
            return False

    def get_scan_progress(self, scan_id):
        """获取扫描进度"""
        try:
            return self.zap.ascan.status(scan_id)
        except Exception as e:
            logger.error(f"获取扫描进度失败: {str(e)}")
            return 0

    def get_alerts(self, task_id, url):
        """获取扫描结果"""
        try:
            alerts = self.zap.core.alerts(baseurl=url)
            return alerts
        except Exception as e:
            TaskLog.add_log(task_id, "ERROR", f"获取ZAP扫描结果失败: {str(e)}")
            raise InternalServerError(f"获取ZAP扫描结果失败: {str(e)}")

    def save_vuls(self, task_id, scan_id, url):
        """保存漏洞到数据库"""
        try:
            alerts = self.get_alerts(task_id, url)
            print(f"ZAP漏洞详情：{alerts}")
            vul_list = []
            severity_map = {
                "0": "info",  # Informational
                "1": "low",  # Low
                "2": "medium",  # Medium
                "3": "high",  # High
                "4": "critical",  # Critical
            }

            for alert in alerts:
                vul = Vulnerability(
                    scan_id=alert.get("id"),
                    scan_source="ZAP",
                    vul_type=alert.get("name"),
                    severity=severity_map.get(alert.get("risk"), "info"),
                    description=alert.get("description"),
                    details=alert.get("solution"),
                    solution=alert.get("reference"),
                    time=datetime.now(),
                )
                vul_list.append(vul)

            if vul_list:
                VulService._save_results(task_id, vul_list)
            result = self.get_scan_progress(scan_id)
            if result == "does_not_exist" or result == "unknown":
                TaskLog.add_log(task_id, "ERROR", f"获取ZAP任务状态失败")
                return True
            if int(result) < 100:
                return False
            return True
        except Exception as e:
            TaskLog.add_log(task_id, "ERROR", f"保存ZAP漏洞失败")
            raise InternalServerError(f"保存ZAP漏洞失败: {str(e)}")
