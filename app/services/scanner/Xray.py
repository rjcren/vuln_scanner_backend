import os
import json
import logging
import subprocess
from flask import current_app
from datetime import datetime, time
from app.models.task_log import TaskLog
from app.models.vulnerability import Vulnerability
from app.services.vul import VulService
from app.utils.exceptions import InternalServerError

logger = logging.getLogger(__name__)

class XrayScanner:
    def __init__(self):
        self.xray_path = current_app.config["XRAY_PATH"]
        self.output_dir = current_app.config["XRAY_OUTPUT_PATH"]
        self.port_pool = PortPool(7777, 7799)
        self.task_processes = {}
        os.makedirs(self.output_dir, exist_ok=True)

    def start_scan(self, task_id):
        """分配端口 + 启动Xray监听"""
        try:
            port = self.port_pool.allocate(task_id)
            output_file = os.path.join(self.output_dir, f"{task_id}_xray.json")
            cmd = [self.xray_path,"webscan","--listen", f"127.0.0.1:{port}","--json-output", output_file]
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.task_processes[task_id] = {"process": process, "port": port, "output": output_file}
            TaskLog.add_log(f"Xray监听中")
            logger.info(f"[Xray] 启动任务 {task_id}：端口 {port}，输出 {output_file}")
            return port
        except Exception as e:
            logger.error(f"[Xray] 启动失败: {str(e)}")
            self.port_pool.release(task_id)
            raise InternalServerError("Xray 启动失败")

    def stop_scan(self, task_id):
        try:
            task = self.task_processes.get(task_id)
            if task:
                task["process"].terminate()
                task["process"].wait()
                logger.info(f"[Xray] 停止任务 {task_id}")
        except Exception as e:
            logger.warning(f"[Xray] 停止失败: {str(e)}")
        self.port_pool.release(task_id)

    def parse_xray_result(self, task_id, result_file):
        """解析Xray JSON结果"""
        try:
            if not os.path.exists(result_file):
                logger.error(f"Xray结果文件不存在: {result_file}")
                return False
            with open(result_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            vul_list = []
            for line in lines:
                try:
                    data = json.loads(line)
                    vul_info = data.get("detail", {})
                    vul_list.append(Vulnerability(
                        scan_id=data.get("create_time"),
                        scan_source="XRAY",
                        vul_type=data.get("plugin"),
                        severity=data.get("severity", "info"),
                        description=data.get("target", ""),
                        details=json.dumps(vul_info),
                        solution=vul_info.get("recommendation", ""),
                        time=datetime.now(),
                    ))
                except Exception as e:
                    TaskLog.add_log(f"单条Xray数据解析失败: {str(e)}")
            if vul_list:
                VulService._save_results(task_id, vul_list)
                return True
        except Exception as e:
            logger.error(f"Xray结果解析失败: {str(e)}")
        return False


import threading
import socket
class PortPool:
    def __init__(self, start=20000, end=20100):
        self.lock = threading.Lock()
        self.available_ports = set(range(start, end + 1))
        self.allocated_ports = {}
    def _is_port_free(self, port):
        """检查端口是否可用（操作系统层面）"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) != 0
    def allocate(self, task_id):
        """分配一个空闲端口给任务"""
        with self.lock:
            for port in sorted(self.available_ports):
                if self._is_port_free(port):
                    self.available_ports.remove(port)
                    self.allocated_ports[task_id] = port
                    return port
            raise RuntimeError("无可用Xray监听端口")
    def release(self, task_id):
        """释放端口"""
        with self.lock:
            port = self.allocated_ports.pop(task_id, None)
            if port:
                self.available_ports.add(port)
    def get(self, task_id):
        """查询某任务当前分配的端口"""
        return self.allocated_ports.get(task_id)
