import logging
import os
from typing import List, Set
from hashlib import md5
from flask import current_app

logger = logging.getLogger(__name__)

from sentence_transformers import SentenceTransformer, util

class VulDeduplicator:
    def __init__(self):
        self.model = None
        self.threshold = 0.9  # 相似度阈值
        
        self.model_path = current_app.config.get("MODEL_PATH")
        if not os.path.exists(self.model_path):
            self.model_path = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"

        # 设置模型缓存目录
        cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "torch", "sentence_transformers")
        os.makedirs(cache_dir, exist_ok=True)
        
        try:
            logger.info("正在加载语义相似度模型...")
            self.model = SentenceTransformer(
                "paraphrase-multilingual-MiniLM-L12-v2",
                cache_folder=cache_dir
            )
            logger.info("模型加载成功")
        except Exception as e:
            logger.error(f"加载模型失败: {e}")
            raise RuntimeError(f"无法初始化语义相似度模型: {e}")

    def is_similar(self, desc1: str, desc2: str) -> bool:
        desc1, desc2 = desc1.strip(), desc2.strip()
        emb1 = self.model.encode(desc1, convert_to_tensor=True)
        emb2 = self.model.encode(desc2, convert_to_tensor=True)
        sim = util.cos_sim(emb1, emb2).item()
        return sim > self.threshold
    
    def get_unique_vulnerabilities(self, new_vuls: List, existing_scan_ids: Set[str]) -> List:
        filtered = [v for v in new_vuls if v.scan_id not in existing_scan_ids]
        for v in filtered:
            v.task_id = getattr(v, "task_id", None)
            logger.debug(f"过滤后的漏洞: {v.description} 任务ID: {v.task_id} 扫描ID: {v.scan_id} 漏洞信息: {v.details}")
        unique_results = []
        seen_sigs = set()
        for item in filtered:
            sig = self._make_signature(item)
            if sig in seen_sigs:
                continue
            if any(self.is_similar(item.description, exist.description) for exist in unique_results):
                continue
            seen_sigs.add(sig)
            unique_results.append(item)
        return unique_results
    @staticmethod
    def _make_signature(vul) -> str:
        desc = vul.description.strip().lower()
        norm = " ".join(desc.split())
        return md5(f"{vul.vul_type}|{norm}".encode()).hexdigest()
