'''漏洞扫描引擎'''
import subprocess
import xml.etree.ElementTree as ET
from app.models import Vulnerability, ScanTask
from app.extensions import db

class ScannerService:
    @staticmethod
    def run_nmap_scan(target: str) -> list:
        """执行Nmap扫描并解析结果"""
        cmd = f"nmap -sV -O -oX - {target}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"Nmap扫描失败: {result.stderr}")

        return ScannerService._parse_nmap_xml(result.stdout)

    @staticmethod
    def _parse_nmap_xml(xml_data: str) -> list:
        """解析Nmap XML输出为漏洞列表"""
        vulns = []
        root = ET.fromstring(xml_data)

        for port in root.findall(".//port"):
            service = port.find("service")
            if service is None:
                continue

            vuln = {
                "cve_id": "NMAP-" + service.get("name", "unknown"),
                "severity": "medium",
                "description": f"{service.get('name')} service detected on port {port.get('portid')}",
                "solution": "Verify service configuration"
            }
            vulns.append(vuln)

        return vulns

    @staticmethod
    def save_vulnerabilities(task_id: int, vulnerabilities: list):
        """保存漏洞到数据库"""
        for vuln_data in vulnerabilities:
            vuln = Vulnerability(
                task_id=task_id,
                cve_id=vuln_data["cve_id"],
                severity=vuln_data["severity"],
                description=vuln_data["description"],
                solution=vuln_data["solution"]
            )
            db.session.add(vuln)
        db.session.commit()