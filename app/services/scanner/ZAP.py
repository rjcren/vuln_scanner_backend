from datetime import datetime
import logging
import os
import re
from urllib.parse import urlparse
from flask import current_app
from zapv2 import ZAPv2
from app.models.task_log import TaskLog
from app.models.vulnerability import Vulnerability
from app.services.vul import VulService
from app.utils.exceptions import InternalServerError

logger = logging.getLogger(__name__)


class ZAP:
    def __init__(self):
        self.ZAP_API_KEY = os.getenv("ZAP_API_KEY", "your_api_key")
        self._ZAP_PROXY = {
            "http": current_app.config["ZAP_API_URL"],
            "https": current_app.config["ZAP_API_URL"],
        }
        self.zap = ZAPv2(apikey=self.ZAP_API_KEY, proxies=self._ZAP_PROXY)

    def start_scan(self, task_id: int, target_url: str, scan_type: str = "full", login_info: str = None):
        """启动主动扫描"""
        SCAN_POLICIES = {
            "full": "Default Policy",
            "sql": {
                "name": "Policy_SQL",
                "scanners": [40018, 40019, 40020, 40021, 40022, 40027],
                "attack_strength": "HIGH",
                "alert_threshold": "HIGH"
            },
            "xss": {
                "name": "Policy_XSS",
                "scanners": [40012, 40014, 40026],
                "dependencies": [40017],
                "alert_threshold": "HIGH"
            },
        }

        policy_config = SCAN_POLICIES.get(scan_type)
        if not policy_config:
            TaskLog.add_log(task_id, "ERROR", f"无效扫描类型: {scan_type}")
            return None

        try:
            context_name = f"ScanContext_{task_id}"
            context_id = self.zap.context.new_context(context_name)

            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            escaped_domain = re.escape(domain)
            context_regex = f"^{parsed_url.scheme}://{escaped_domain}/.*"

            self.zap.context.include_in_context(context_name, context_regex)
            self.zap.context.set_context_in_scope(context_name, True)
            TaskLog.add_log(task_id, "INFO", f"ZAP上下文已配置: {context_regex}")
        except Exception as e:
            logger.error(f"ZAP上下文配置失败: {str(e)}")
            TaskLog.add_log(task_id, "ERROR", "ZAP上下文配置失败")
            return None

        if login_info:
            try:
                TaskLog.add_log(task_id, "INFO", f"login_info: {login_info}")
                login_infos = login_info.split(",")
                auth_method_config = f"loginUrl={login_infos[0]}&usernameParam={login_infos[1]}&passwordParam={login_infos[2]}"
                self.zap.authentication.set_authentication_method(
                    context_id,
                    "formBasedAuthentication",
                    auth_method_config
                )
                self.zap.users.new_user(context_id, "auth_user")
                self.zap.forcedUser.set_forced_user(context_id, 0)
                self.zap.forcedUser.set_forced_user_mode_enabled(True)
            except Exception as e:
                logger.error(f"ZAP添加自动登录失败: {str(e)}")
                TaskLog.add_log(task_id, "ERROR", "ZAP添加自动登录失败")
                return None

        try:
            if scan_type == "full":
                scan_policy_name = "Default Policy"
                self.zap.ascan.enable_all_scanners()
                self.zap.ascan.set_policy_attack_strength(scan_policy_name, "HIGH")
            else:
                scan_policy_name = policy_config["name"]
                # 创建扫描策略
                self.zap.ascan.add_scan_policy(scan_policy_name)
                scanners = policy_config.get("scanners", [])
                dependencies = policy_config.get("dependencies", [])

                for sid in dependencies:
                    self.zap.ascan.enable_scanners(scanpolicyname=scan_policy_name, ids=str(sid))
                for sid in scanners:
                    self.zap.ascan.enable_scanners(scanpolicyname=scan_policy_name, ids=str(sid))
                    if "attack_strength" in policy_config:
                        self.zap.ascan.set_scanner_attack_strength(
                            id=str(sid),
                            attackstrength=policy_config["attack_strength"],
                            scanpolicyname=scan_policy_name
                        )
                    self.zap.ascan.set_scanner_alert_threshold(
                        id=str(sid),
                        alertthreshold=policy_config["alert_threshold"],
                        scanpolicyname=scan_policy_name
                    )

            self.zap.urlopen(target_url)
            self.zap.core.access_url(target_url, followredirects=True)
            
            scan_id = self.zap.ascan.scan(
                url=target_url,
                recurse=True,
                inscopeonly=False,
                scanpolicyname=scan_policy_name
            )
            if not scan_id.isdigit():
                TaskLog.add_log(task_id, "ERROR", f"ZAP扫描启动失败: {scan_id}")
                return None
            TaskLog.add_log(task_id, "INFO", f"ZAP扫描已启动: scan_id={scan_id}")
            return scan_id
        except Exception as e:
            logger.error(f"ZAP扫描启动失败: {str(e)}")
            TaskLog.add_log(task_id, "ERROR", "ZAP扫描启动失败")
            return None

    def stop_scan(self, scan_id: str):
        try:
            result = self.zap.ascan.stop(scan_id)
            if result != "OK":
                logger.error(f"停止ZAP扫描失败: {result}")
                return False
            return True
        except Exception as e:
            logger.error(f"停止ZAP扫描异常: {str(e)}")
            return False

    def get_scan_progress(self, scan_id):
        try:
            return self.zap.ascan.status(scan_id)
        except Exception as e:
            logger.error(f"获取扫描进度失败: {str(e)}")
            return "does_not_exist"

    def get_alerts(self, task_id, url):
        try:
            alerts = self.zap.core.alerts(baseurl=url)
            return alerts
        except Exception as e:
            TaskLog.add_log(task_id, "ERROR", f"获取ZAP扫描结果失败: {str(e)}")
            raise InternalServerError(f"获取ZAP扫描结果失败: {str(e)}")

    def save_vuls(self, task_id, scan_id, url):
        try:
            alerts = self.get_alerts(task_id, url)
            print(f"ZAP漏洞详情：{alerts}")
            vul_list = []
            severity_map = {
                "0": "info",
                "1": "low",
                "2": "medium",
                "3": "high",
                "4": "critical",
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
            TaskLog.add_log(task_id, "ERROR", f"保存ZAP漏洞失败: {str(e)}")
            raise InternalServerError(f"保存ZAP漏洞失败: {str(e)}")
