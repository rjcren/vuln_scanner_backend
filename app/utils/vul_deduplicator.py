from collections import defaultdict
import logging
import os
from pathlib import Path
from typing import List, Set
from hashlib import md5
from flask import current_app
import torch
from app.models.vulnerability import Vulnerability
from app.utils.exceptions import InternalServerError
from sentence_transformers import SentenceTransformer, util
import numpy as np

logger = logging.getLogger(__name__)

class VulDeduplicator:
    def __init__(self, threshold: float = 0.82):
        # 初始化时共享预加载模型
        if not hasattr(current_app, 'sentence_model'):
            model_path = Path("./language-models/paraphrase-multilingual-MiniLM-L12-v2")
            current_app.sentence_model = SentenceTransformer(str(model_path))
        self.model = current_app.sentence_model
        self.threshold = threshold

    def _preprocess(self, text: str) -> str:
        """统一文本预处理流程"""
        return text.strip().lower().replace('\n', ' ').replace('\t', ' ')[:500]  # 限制长度防止内存溢出

    def deduplicate(self, new_vuls: List[Vulnerability], existing_dict: dict) -> List[Vulnerability]:
        # 阶段1：基础过滤
        valid_vuls = []
        seen_scan_ids = set()
        for vul in new_vuls:
            if vul.scan_id in existing_dict.get(vul.scan_source, {}): continue
            if vul.scan_id in seen_scan_ids: continue
            seen_scan_ids.add(vul.scan_id)
            valid_vuls.append(vul)
        
        # 无有效漏洞或仅剩单个漏洞时直接返回
        if len(valid_vuls) <= 1:
            return valid_vuls

        # 阶段2：准备对比数据
        # 收集所有需对比的现有漏洞（其他工具）
        other_tools_vuls = []
        for tool, vul_map in existing_dict.items():
            if tool != valid_vuls[0].scan_source:  # 排除当前工具
                other_tools_vuls.extend(vul_map.values())
        
        # 阶段3：批量编码
        batch_descs = [self._preprocess(v.description) for v in valid_vuls]
        batch_embeddings = self.model.encode(batch_descs, batch_size=64, convert_to_tensor=True)
        
        # 阶段4：跨工具相似度匹配
        keep_mask = [True] * len(valid_vuls)
        if other_tools_vuls:
            # 现有漏洞编码（带缓存）
            cache_key = md5(str([v.description for v in other_tools_vuls]).encode()).hexdigest()
            if not hasattr(self, '_cache_embeddings') or self._cache_key != cache_key:
                self._cache_embeddings = self.model.encode(
                    [self._preprocess(v.description) for v in other_tools_vuls],
                    batch_size=64,
                    convert_to_tensor=True
                )
                self._cache_key = cache_key
            
            # 矩阵式计算相似度
            similarity_matrix = util.cos_sim(batch_embeddings, self._cache_embeddings)
            max_similarities, _ = torch.max(similarity_matrix, dim=1)
            for i, sim in enumerate(max_similarities):
                if sim > self.threshold:
                    keep_mask[i] = False

        # 阶段5：同批次跨工具检查
        tool_groups = defaultdict(list)
        for idx, vul in enumerate(valid_vuls):
            tool_groups[vul.scan_source].append((idx, vul))
        
        # 仅当存在多个工具时进行跨批次检查
        if len(tool_groups) > 1:
            cross_embeddings = []
            cross_indices = []
            for tool, items in tool_groups.items():
                indices, vuls = zip(*items)
                descs = [self._preprocess(v.description) for v in vuls]
                cross_embeddings.append(self.model.encode(descs, convert_to_tensor=True))
                cross_indices.extend(indices)
            
            combined_embeddings = torch.cat(cross_embeddings)
            tool_labels = [tool for tool, items in tool_groups.items() for _ in items]
            
            # 构建工具掩码矩阵
            mask = torch.zeros((len(tool_labels), len(tool_labels)), dtype=torch.bool)
            for i in range(len(tool_labels)):
                for j in range(len(tool_labels)):
                    if tool_labels[i] != tool_labels[j]:
                        mask[i][j] = True
            
            similarity_matrix = util.cos_sim(combined_embeddings, combined_embeddings)
            masked_matrix = similarity_matrix * mask.float()
            
            # 标记需要排除的项
            for i in range(masked_matrix.size(0)):
                if keep_mask[cross_indices[i]] and torch.any(masked_matrix[i] > self.threshold):
                    # 与同批次其他工具存在相似时，保留最早最高危的
                    candidates = [valid_vuls[cross_indices[i]]]
                    for j in torch.where(masked_matrix[i] > self.threshold)[0].tolist():
                        candidates.append(valid_vuls[cross_indices[j]])
                    representative = self._select_representative(candidates)
                    # 标记非代表的项
                    for cand in candidates:
                        if cand is not representative:
                            idx = valid_vuls.index(cand)
                            keep_mask[idx] = False

        return [vul for i, vul in enumerate(valid_vuls) if keep_mask[i]]

    def _select_representative(self, candidates: list) -> Vulnerability:
        """选择最高危且最早的漏洞"""
        max_sev = max(candidates, key=lambda x: SEVERITY_ORDER[x.severity])
        final_candidates = [v for v in candidates if v.severity == max_sev.severity]
        return min(final_candidates, key=lambda x: x.time)

# 辅助常量
SEVERITY_ORDER = {"critical":4, "high":3, "medium":2, "low":1, "info":0}