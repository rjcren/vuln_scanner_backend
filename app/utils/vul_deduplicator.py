import logging
from typing import List, Set
from hashlib import md5

logger = logging.getLogger(__name__)

from sentence_transformers import SentenceTransformer, util

class VulDeduplicator:
    try:
        model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")  # 多语言模型
    except Exception as e: 
        print(f"加载模型失败: {e}")
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
        unique_results = []
        seen_sigs = set()
        for item in filtered:
            sig = self._make_signature(item)
            if sig in seen_sigs:
                continue
            if any(self.is_similar(item.description, exist.description)
                   and item.target_url == exist.target_url
                   for exist in unique_results):
                continue
            seen_sigs.add(sig)
            unique_results.append(item)
        return unique_results
    @staticmethod
    def _make_signature(vul) -> str:
        desc = vul.description.strip().lower()
        norm = " ".join(desc.split())
        return md5(f"{vul.target_url}|{vul.vul_type}|{norm}".encode()).hexdigest()
