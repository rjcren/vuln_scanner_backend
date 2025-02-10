'''扫描工具封装'''
import subprocess
import xml.etree.ElementTree as ET
from app.utils.exceptions import ScanExecutionError

class ScannerUtils:
    @staticmethod
    def run_nmap(target: str, args: str = "-sV -O") -> dict:
        """执行Nmap扫描并解析结果"""
        cmd = f"nmap {args} -oX - {target}"
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            return ScannerUtils._parse_nmap_xml(result.stdout)
        except subprocess.CalledProcessError as e:
            raise ScanExecutionError(f"Nmap扫描失败: {e.stderr}")

    @staticmethod
    def _parse_nmap_xml(xml_data: str) -> dict:
        """解析Nmap XML输出"""
        root = ET.fromstring(xml_data)
        scan_result = {"ports": []}

        for port in root.findall(".//port"):
            port_data = {
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": port.find("service").get("name") if port.find("service") else "unknown"
            }
            scan_result["ports"].append(port_data)

        return scan_result

    @staticmethod
    def run_zap_scan(target_url: str, api_key: str) -> list:
        """调用OWASP ZAP API执行扫描"""
        # 示例：实际需实现ZAP API调用逻辑
        return [{
            "alert": "XSS Vulnerability",
            "risk": "High"
        }]