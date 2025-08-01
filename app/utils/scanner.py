"""扫描工具模块"""
import subprocess
from pathlib import Path
from typing import Dict, List
import xml.etree.ElementTree as ET
import logging
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash
from flask import current_app
from app.utils.exceptions import InternalServerError, ValidationError
from app.utils.validation import InputValidator

logger = logging.getLogger(__name__)

class ScannerUtils:
    """扫描工具集（整合Nmap、ZAP等工具调用）"""

    @staticmethod
    def run_nmap_scan(target: str) -> List[Dict]:
        """执行Nmap端口扫描"""
        if not InputValidator.validate_url(target):
            raise ValidationError("无效的扫描目标")

        output_file = Path(current_app.config["SCAN_OUTPUT_DIR"]) / f"nmap_{datetime.now(timezone.utc):%Y%m%d%H%M%S}.xml"

        try:
            subprocess.run([
                "nmap",
                "-oX", str(output_file),
                "-sV",
                "--open",
                target
            ], check=True, capture_output=True)

            return ScannerUtils.parse_nmap_results(output_file)

        except subprocess.CalledProcessError as e:
            raise InternalServerError(f"端口扫描服务暂时不可用: Nmap扫描失败: {str(e)}")

    @staticmethod
    def parse_nmap_results(xml_path: Path) -> List[Dict]:
        """解析Nmap XML结果"""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            results = []

            for host in root.findall("host"):
                ip = host.find("address").get("addr")
                for port in host.findall("ports/port"):
                    port_data = {
                        "ip": ip,
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "service": port.find("service").get("name") if port.find("service") else "unknown",
                        "version": port.find("service").get("version") if port.find("service") else ""
                    }
                    results.append(port_data)

            return [{
                "type": "port",
                "severity": "info",
                "description": f"发现开放端口: {item["port"]}/{item["protocol"]} ({item["service"]})"
            } for item in results]

        except ET.ParseError as e:
            raise InternalServerError(f"扫描结果解析异常: XML解析失败: {str(e)}")

    @staticmethod
    def run_zap_scan(target_url: str, api_key: str) -> List[Dict]:
        """执行OWASP ZAP扫描"""
        if not InputValidator.validate_url(target_url):
            raise ValidationError("无效的扫描目标")

        try:
            # ZAP API调用逻辑
            result = subprocess.run([
                "zap-api-scan.py",
                "-t", target_url,
                "-f", "openapi",
                "-k", api_key
            ], check=True, capture_output=True)

            return ScannerUtils.parse_zap_output(result.stdout.decode())

        except subprocess.CalledProcessError as e:
            logger.error(f"ZAP扫描失败: {str(e)}")
            raise InternalServerError("漏洞扫描服务暂时不可用")

    @staticmethod
    def parse_zap_output(output: str) -> List[Dict]:
        """解析ZAP扫描结果"""
        alerts = []
        # 这里添加具体的解析逻辑
        return alerts
