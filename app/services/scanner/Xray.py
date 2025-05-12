import os
import json
import signal
import logging
import subprocess
import threading
import socket
from flask import current_app
from datetime import datetime
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
        """启动Xray被动扫描监听"""
        try:
            # 分配端口并验证可用性
            port = self.port_pool.allocate(task_id)
            
            # 准备输出文件路径
            output_file = os.path.join(self.output_dir, f"{task_id}_xray.json")
            stdout_log = os.path.join(self.output_dir, f"{task_id}_xray_stdout.log")
            stderr_log = os.path.join(self.output_dir, f"{task_id}_xray_stderr.log")

            # 构建启动命令
            cmd = [
                self.xray_path, 
                "webscan",
                "--listen", f"127.0.0.1:{port}",
                "--json-output", output_file,
                # 添加资源限制参数（根据Xray版本调整）
                "--max-cpu=90",
                "--max-memory=4096"
            ]

            # 启动子进程
            with open(stdout_log, 'w') as f_stdout, open(stderr_log, 'w') as f_stderr:
                process = subprocess.Popen(
                    cmd,
                    cwd=os.path.dirname(self.xray_path),
                    stdout=f_stdout,
                    stderr=f_stderr,
                    start_new_session=True  # 创建新进程组
                )

            # 记录进程信息
            self.task_processes[task_id] = {
                "process": process,
                "port": port,
                "output": output_file,
                "start_time": datetime.now()
            }

            TaskLog.add_log(task_id, "INFO", f"Xray监听启动成功，端口: {port}")
            logger.info(f"[Xray] 任务{task_id}启动成功 PID:{process.pid} 端口:{port}")
            return port

        except Exception as e:
            self.port_pool.release(task_id)
            logger.error(f"[Xray] 启动失败: {str(e)}", exc_info=True)
            raise InternalServerError("Xray服务启动失败")

    def stop_scan(self, task_id):
        """停止扫描并释放资源"""
        try:
            task = self.task_processes.pop(task_id, None)
            if task:
                process = task["process"]
                port = task["port"]
                
                # 终止整个进程组
                try:
                    if hasattr(os, 'killpg'):
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    else:
                        process.terminate()
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    logger.warning(f"强制终止Xray进程 {process.pid}")
                    process.kill()
                
                # 记录运行时长
                duration = datetime.now() - task["start_time"]
                logger.info(f"[Xray] 任务{task_id}已停止 运行时长: {duration}")
                TaskLog.add_log(task_id, "INFO", f"Xray监听已停止 运行时长: {duration}")

        except Exception as e:
            logger.error(f"[Xray] 停止任务异常: {str(e)}", exc_info=True)
        finally:
            self.port_pool.release(task_id)

    def parse_results(self, task_id):
        """解析扫描结果"""
        task = self.task_processes.get(task_id)
        if not task:
            logger.error(f"无效任务ID: {task_id}")
            return False

        output_file = task["output"]
        if not os.path.exists(output_file):
            logger.error(f"结果文件不存在: {output_file}")
            return False

        try:
            vul_list = []
            with open(output_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        vul = self._parse_vulnerability(data)
                        if vul:
                            vul_list.append(vul)
                    except json.JSONDecodeError:
                        logger.warning(f"无效JSON数据: {line}")
                        continue

            if vul_list:
                VulService._save_results(task_id, vul_list)
                logger.info(f"[Xray] 任务{task_id}解析到{len(vul_list)}个漏洞")
                return True
            return False
        except Exception as e:
            logger.error(f"结果解析失败: {str(e)}", exc_info=True)
            return False

    def _parse_vulnerability(self, data):
        """解析单个漏洞数据"""
        try:
            return Vulnerability(
                scan_id=data.get("create_time", datetime.now().strftime("%Y%m%d%H%M%S")),
                scan_source="XRAY",
                vul_type=data.get("plugin", "unknown"),
                severity=data.get("severity", "info").lower(),
                description=data.get("target", {}).get("url", ""),
                details=json.dumps(data.get("detail", {})),
                solution=data.get("detail", {}).get("recommendation", ""),
                time=datetime.fromisoformat(data["create_time"].replace('Z', '+00:00')),
                risk_score=self._calc_risk_score(data.get("severity"))
            )
        except Exception as e:
            logger.warning(f"漏洞数据解析异常: {str(e)}")
            return None

    def _calc_risk_score(self, severity):
        """将文本型严重程度转换为数值"""
        mapping = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0}
        return mapping.get(severity.lower(), 1.0)

class PortPool:
    """端口资源池管理"""
    def __init__(self, start_port, end_port):
        self.lock = threading.Lock()
        self.available = list(range(start_port, end_port + 1))
        self.allocated = {}  # task_id: port

    def allocate(self, task_id):
        """分配可用端口"""
        with self.lock:
            if not self.available:
                raise RuntimeError("无可用端口")

            # 优先复用最近释放的端口
            for port in reversed(self.available):
                if self._is_port_available(port):
                    self.available.remove(port)
                    self.allocated[task_id] = port
                    return port
            raise RuntimeError("未找到可用端口")

    def release(self, task_id):
        """释放端口"""
        with self.lock:
            port = self.allocated.pop(task_id, None)
            if port and port not in self.available:
                self.available.append(port)

    def _is_port_available(self, port):
        """系统级端口可用性检查"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex(('127.0.0.1', port)) != 0

    def get_port(self, task_id):
        """查询任务端口"""
        with self.lock:
            return self.allocated.get(task_id)