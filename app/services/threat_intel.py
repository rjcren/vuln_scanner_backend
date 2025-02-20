from datetime import datetime, timedelta
import requests
from flask import abort
from typing import List, Dict
from app.extensions import db
from app.models.threat_intel import ThreatIntel
from app.utils.logger import setup_logger
from app.utils.exceptions import ServerExecutionError

logger = setup_logger(__name__)

class ThreatIntelService:
    # 官方CVE API端点（示例使用NVD API）
    CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    # 默认同步最近24小时的数据
    DEFAULT_LOOKBACK_HOURS = 24

    @classmethod
    def sync_from_cve(cls, lookback_hours: int = None) -> List[ThreatIntel]:
        """
        从CVE数据库同步威胁情报
        :param lookback_hours: 回溯时间（小时）
        :return: 新增的威胁情报记录列表
        """
        lookback = lookback_hours or cls.DEFAULT_LOOKBACK_HOURS
        start_date = datetime.utcnow() - timedelta(hours=lookback)

        try:
            # 1. 获取增量数据
            cve_data = cls._fetch_cve_data(start_date)

            # 2. 解析数据
            parsed_data = cls._parse_cve_response(cve_data)

            # 3. 保存到数据库
            new_records = cls._save_threat_intel(parsed_data)

            logger.info(f"成功同步 {len(new_records)} 条CVE记录")
            return new_records

        except Exception as e:
            logger.error(f"威胁情报同步失败: {str(e)}")
            abort(ServerExecutionError(f"CVE数据同步失败: {str(e)}"))

    @classmethod
    def _fetch_cve_data(cls, start_date: datetime) -> Dict:
        """从NVD API获取CVE数据"""
        params = {
            "startIndex": 0,
            "resultsPerPage": 2000,  # 最大允许值
            "modStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00"),
            "modEndDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00")
        }

        try:
            response = requests.get(cls.CVE_API_URL, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"CVE API请求失败: {str(e)}")
            raise
        except ValueError as e:
            logger.error(f"无效的API响应: {str(e)}")
            raise

    @classmethod
    def _parse_cve_response(cls, response_data: Dict) -> List[Dict]:
        """解析NVD API响应"""
        parsed = []
        for item in response_data.get("result", {}).get("CVE_Items", []):
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            description = next(
                (desc["value"] for desc in item["cve"]["description"]["description_data"]
                 if desc["lang"] == "en"),
                "No description available"
            )

            # 提取CVSSv3基础评分
            cvssv3 = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})

            parsed.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvssv3.get("baseScore"),
                "severity": cvssv3.get("baseSeverity"),
                "published_date": item["publishedDate"],
                "last_modified": item["lastModifiedDate"]
            })
        return parsed

    @classmethod
    def _save_threat_intel(cls, parsed_data: List[Dict]) -> List[ThreatIntel]:
        """保存到数据库（去重处理）"""
        new_records = []
        for item in parsed_data:
            # 检查是否已存在
            existing = ThreatIntel.query.filter_by(cve_id=item["cve_id"]).first()
            if existing:
                # 更新现有记录
                existing.description = item["description"]
                existing.cvss_score = item["cvss_score"]
                existing.severity = item["severity"]
                existing.last_modified = item["last_modified"]
            else:
                # 创建新记录
                new_rec = ThreatIntel(
                    cve_id=item["cve_id"],
                    description=item["description"],
                    cvss_score=item["cvss_score"],
                    severity=item["severity"],
                    published_date=item["published_date"],
                    last_modified=item["last_modified"]
                )
                db.session.add(new_rec)
                new_records.append(new_rec)

        db.session.commit()
        return new_records

    @classmethod
    def get_cve_details(cls, cve_id: str) -> ThreatIntel:
        """查询特定CVE的详细信息"""
        return ThreatIntel.query.filter_by(cve_id=cve_id).first()

    @classmethod
    def search_vulnerabilities(cls, keyword: str) -> List[ThreatIntel]:
        """搜索漏洞情报"""
        return ThreatIntel.query.filter(
            ThreatIntel.description.ilike(f"%{keyword}%")
        ).limit(100).all()