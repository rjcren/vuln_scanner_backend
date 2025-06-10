from datetime import datetime, timezone
import logging
import os
from flask import current_app
import requests
from app.models.task_log import TaskLog
from app.models.vulnerability import Vulnerability
from app.services.vul import VulService
from app.utils.exceptions import AppException, InternalServerError
from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger(__name__)

# 禁用https证书相关警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class AWVS:
    def __init__(self):
        self.api_base_url = current_app.config["AWVS_API_URL"]
        _api_key = current_app.config["AWVS_API_KEY"]
        self.auth_headers = {"X-Auth": _api_key, "content-type": "application/json"}

        self.targets_api = f"{self.api_base_url}/api/v1/targets"
        self.scan_api = f"{self.api_base_url}/api/v1/scans"
        # self.report_api = f"{self.api_base_url}/api/v1/reports"
        # self.vuln_api = f"{api_base_url}/api/v1/vulnerabilities"

        # self.report_template_dict = {
        #     "affected_items": "11111111-1111-1111-1111-111111111115",
        #     "cwe_2011": "11111111-1111-1111-1111-111111111116",
        #     "developer": "11111111-1111-1111-1111-111111111111",
        #     "executive_summary": "11111111-1111-1111-1111-111111111113",
        #     "hipaa": "11111111-1111-1111-1111-111111111114",
        #     "iso_27001": "11111111-1111-1111-1111-111111111117",
        #     "nist_SP800_53": "11111111-1111-1111-1111-111111111118",
        #     "owasp_top_10_2013": "11111111-1111-1111-1111-111111111119",
        #     "pci_dss_3.2": "11111111-1111-1111-1111-111111111120",
        #     "quick": "11111111-1111-1111-1111-111111111112",
        #     "sarbanes_oxley": "11111111-1111-1111-1111-111111111121",
        #     "scan_comparison": "11111111-1111-1111-1111-111111111124",
        #     "stig_disa": "11111111-1111-1111-1111-111111111122",
        #     "wasc_threat_classification": "11111111-1111-1111-1111-111111111123"
        # }

        self.profile_dict = {
            "full": "11111111-1111-1111-1111-111111111111",
            "quick": "11111111-1111-1111-1111-111111111112",
            "xss": "11111111-1111-1111-1111-111111111116",
            "sql": "11111111-1111-1111-1111-111111111113",
            "pass": "11111111-1111-1111-1111-111111111115",
            "crawl_only": "11111111-1111-1111-1111-111111111117",
        }

    def add_url(self, task_id, url, login_url=None, login_username=None, login_password=None):
        """添加url到AWVS"""
        try:
            data = {"address": url, "description": "自动化添加，请勿删除"}
            res = requests.post(
                self.targets_api, headers=self.auth_headers, json=data, verify=False
            )
            if res.status_code == 201:
                if login_url:
                    d = {
                        "login": {
                            "kind": "automatic",
                            "credentials": {
                                "enabled": True,
                                "username": login_username,
                                "password": login_password,
                                "url": login_url,
                            },
                        }
                    }
                    login_res = requests.patch(f"{self.targets_api}/{res.json()["target_id"]}/configuration", headers=self.auth_headers, json=d, verify=False)
                    print(f"login_res:{login_res}")
                return res.json()["target_id"]
            else:
                error_message = f"HTTP {res.status_code}: {res.text}"
                logger.info(f"AWVS添加url失败: {error_message}")
        except AppException:
            raise
        except Exception as e:
            TaskLog.add_log(task_id, "ERROR", "AWVS添加url失败")
            logger.error(f"AWVS添加url失败 {str(e)}")
        return None

    def start_scan(self, task_id, target_id, profile_key="full"):
        """运行AWVS扫描任务"""
        data = {
            "target_id": target_id,
            "profile_id": self.profile_dict.get(profile_key),
            "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
        }
        try:
            res = requests.post(
                self.scan_api, json=data, headers=self.auth_headers, verify=False
            )
            # logger.error(data)
            if res.status_code == 201:
                TaskLog.add_log(task_id, "INFO", "AWVS扫描启动成功")
                # logger.info(res.json())
                return res.json()["scan_id"]
            else:
                error_message = f"HTTP {res.status_code}: {res.text}"
                TaskLog.add_log(task_id, "ERROR", f"AWVS扫描启动失败: {error_message}")
        except Exception as e:
            TaskLog.add_log(task_id, "ERROR", "AWVS扫描启动失败")
            logger.error(f"AWVS启动扫描失败 {str(e)}")
        return None
    
    def set_proxy(self, task_id, target_id, port):
        try:
            data = {
                "proxy": {
                    "address": "172.17.0.1",
                    "enabled": True,
                    "port": port,
                    "protocol": "http"
                }
            }
            res = requests.patch(
                f"{self.targets_api}/{target_id}/configuration",
                headers=self.auth_headers,
                json=data,
                verify=False,
            )
            if not (res.status_code >= 200 and res.status_code < 300):
                error_message = f"HTTP {res.status_code}: {res.text}"
                TaskLog.add_log(task_id, "ERROR", f"AWVS设置代理失败: {error_message}")
        except Exception as e:
            TaskLog.add_log(task_id, "ERROR", "AWVS设置代理失败")
            logger.error(f"AWVS设置代理失败 {str(e)}")

    def delete(self, scan_id):
        try:
            target_id = self.get_scan(scan_id).get("target_id")
            delete_api = None
            if target_id:
                delete_api = f"{self.targets_api}/{target_id}"
            else:
                delete_api = f"{self.targets_api}/{scan_id}"
            # print(scan_id, target_id, delete_api)
        except Exception as e:
            logger.error(f"AWVS删除扫描失败 {str(e)}")

    def stop_scan(self, scan_id):
        try:
            stop_api = f"{self.scan_api}/{scan_id}/abort"
            res = requests.post(stop_api, headers=self.auth_headers, verify=False)

            if res.status_code != 204: logger.error(f"停止AWVS扫描失败: HTTP {res.status_code}: {res.text}")
        except Exception as e:
            raise InternalServerError(f"任务停止失败: {str(e)}")

    def get_scan(self, scan_id: str):
        try:
            res = requests.get(
                url=f"{self.scan_api}/{scan_id}",
                headers=self.auth_headers,
                verify=False,
            )
            return res.json()
        except Exception as e:
            raise InternalServerError(f"获取扫描任务失败{str(e)}")

    def get_vuls(self, scan_id, scan_session_id):
        """获取任务漏洞列表"""
        scan_result_api = (
            f"{self.scan_api}/{scan_id}/results/{scan_session_id}/vulnerabilities"
        )
        try:
            response = requests.get(
                scan_result_api, headers=self.auth_headers, verify=False
            )
            vuln_list = response.json().get("vulnerabilities", [])
            return vuln_list
        except Exception as e:
            raise InternalServerError(f"获取漏洞列表失败{str(e)}")

    def get_vuln_detail(self, scan_id, scan_session_id, vuln_id):
        """获取任务中漏洞具体的漏洞信息"""
        scan_vuln_detail_api = f"{self.scan_api}/{scan_id}/results/{scan_session_id}/vulnerabilities/{vuln_id}"
        try:
            response = requests.get(
                scan_vuln_detail_api, headers=self.auth_headers, verify=False
            )
            return response.json()
        except Exception as e:
            raise InternalServerError(f"获取漏洞列表失败: {str(e)}")

    def get_vuln_statistics(self, scan_id, session_id):
        """获取漏洞概述，主要用来获取漏洞时间"""
        scan_vuln_statistics_api = (
            f"{self.scan_api}/{scan_id}/results/{session_id}/statistics"
        )
        try:
            response = requests.get(
                scan_vuln_statistics_api, headers=self.auth_headers, verify=False
            )
            return response.json()
        except Exception as e:
            raise InternalServerError(f"获取漏洞概述失败: {str(e)}")

    def save_vuls(self, task_id, scan_id):
        """AWVS获取指定任务的漏洞"""
        try:
            res = self.get_scan(scan_id)
            progress = res.get("current_session", {}).get("progress")
            session_id = res.get("current_session", {}).get("scan_session_id")
            if (
                not session_id
            ):  # 因AWVS任务状态类型颇多，此处会出现scan_session_id返回值为空的情况，故请求到有为止
                return False
            # 获取扫描的结果列表
            vuln_list = self.get_vuls(scan_id, session_id)
            if vuln_list:
                vul_statistics = self.get_vuln_statistics(scan_id, session_id)
                statisticses = (
                    vul_statistics.get("scanning_app")
                    .get("wvs")
                    .get("main")
                    .get("vulns")
                )
                vul_detail_list = []
                map = {
                    "0": "info",
                    "1": "low",
                    "2": "medium",
                    "3": "high",
                    "4": "critical",
                }
                for vul in vuln_list:
                    try:
                        num = None
                        for index, sta in enumerate(statisticses):
                            if vul.get("vuln_id") == sta.get("vuln_id"):
                                num = index
                                break
                        if not num:
                            continue
                        vul_detail = self.get_vuln_detail(
                            scan_id, session_id, vul.get("vuln_id")
                        )
                        vul_detail_list.append(
                            Vulnerability(
                                task_id=task_id,
                                scan_id=vul.get("vuln_id"),
                                scan_source="AWVS",
                                vul_type=vul_detail.get("vt_name"),
                                severity=map.get(
                                    str(vul_detail.get("severity")), "info"
                                ),
                                description=vul_detail.get("description"),
                                details=vul_detail.get("details"),
                                solution=vul_detail.get("recommendation"),
                                time=datetime.fromisoformat(
                                    statisticses[num].get("time")
                                ).replace(tzinfo=timezone.utc),  # 确保使用UTC时间
                            )
                        )
                    except Exception as e:
                        logger.error(f"获取漏洞详情失败: {str(e)}")
                # 保存到数据库
                if vul_detail_list:
                    VulService._save_results(task_id, vul_detail_list)
            res = self.get_scan(scan_id)
            new_progress = res.get("current_session", {}).get("progress", 100)
            if (new_progress == 100 and progress < 100) or new_progress < 100:
                return False
            return True
        except AppException:
            raise
        except Exception as e:
            TaskLog.add_log(task_id, "ERROR", f"集成AWVS扫描结果失败: {str(e)}")
            raise InternalServerError(f"获取AWVS漏洞失败: {str(e)}")
