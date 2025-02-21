"""扫描引擎工具类 - 负责底层工具调用和结果解析"""
import subprocess
from pathlib import Path
from typing import Dict, List
import xml.etree.ElementTree as ET
from app.utils.exceptions import InternalServerError
import logging

logger = logging.getLogger(__name__)

class ScannerEngine:
    """基础扫描引擎"""

    @staticmethod
    def run_nmap(target: str, args: str = "-sV -O") -> List[Dict]:
        """执行Nmap扫描"""
        cmd = f"nmap {args} {target}"
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1800  # 30分钟超时
            )
            return NmapParser.parse(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap扫描失败: {e.stderr}")
            raise InternalServerError("Nmap扫描失败")
        except subprocess.TimeoutExpired:
            logger.error("Nmap扫描超时")
            raise InternalServerError("Nmap扫描超时")

    @staticmethod
    def run_zap(target_url: str) -> List[Dict]:
        """执行ZAP扫描（需预先启动ZAP服务）"""
        # 示例实现，实际需调用ZAP API
        return [
            {
                "type": "web",
                "severity": "high",
                "description": "检测到SQL注入漏洞"
            }
        ]

class NmapParser:
    """Nmap结果解析器"""

    @staticmethod
    def parse(xml_output: str) -> List[Dict]:
        """解析XML格式的Nmap输出"""
        try:
            root = ET.fromstring(xml_output)
            results = []

            for host in root.findall('host'):
                ip = host.find('address').get('addr')
                for port in host.findall('.//port'):
                    port_data = {
                        "ip": ip,
                        "port": port.get('portid'),
                        "protocol": port.get('protocol'),
                        "service": port.find('service').get('name') if port.find('service') else 'unknown'
                    }
                    results.append(port_data)

            return [{
                "type": "port",
                "severity": "info",
                "description": f"发现开放端口: {item['port']}/{item['protocol']} ({item['service']})"
            } for item in results]

        except ET.ParseError as e:
            logger.error(f"Nmap结果解析失败: {str(e)}")
            return []