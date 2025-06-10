import os
import json
from random import randint
import signal
import logging
import subprocess
import threading
import socket
from flask import current_app
from datetime import datetime, timezone
from app.models.task_log import TaskLog
from app.models.vulnerability import Vulnerability
from app.services.vul import VulService
from app.utils.exceptions import InternalServerError
from app.extensions import redis_client
from app.utils.portPoll import PortPool
import psutil

logger = logging.getLogger(__name__)

class Xray:
    def __init__(self, xray_path=None, output_dir=None):
        self.xray_path = xray_path or current_app.config.get("XRAY_PATH")
        self.output_dir = output_dir or current_app.config.get("XRAY_OUTPUT_PATH")
        self.port_pool = PortPool(7777, 7799)
        self.parse_lock = threading.Lock()
        os.makedirs(self.output_dir, exist_ok=True)
        
    def start_scan(self, task_id):
        """启动Xray被动扫描监听"""
        process = None
        try:
            port = self.port_pool.allocate(task_id)
            
            output_file = os.path.join(self.output_dir, f"{task_id}_xray.json")
            stdout_log = os.path.join(self.output_dir, f"{task_id}_xray_stdout.log")
            stderr_log = os.path.join(self.output_dir, f"{task_id}_xray_stderr.log")

            cmd = [
                self.xray_path, 
                "webscan",
                "--listen", f"0.0.0.0:{port}",
                "--json-output", output_file
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

            # 记录进程信息到Redis（不存储process对象）
            task_info = {
                "pid": process.pid,
                "port": port,
                "output": output_file,
                "parsed_positions": 0,
                "start_time": datetime.now().isoformat(),
                "last_mtime": 0,
            }
            redis_client.set(f"xray_task_{task_id}", json.dumps(task_info))
            
            logger.info(f"[Xray] 任务{task_id}启动成功 PID:{process.pid} 端口:{port}")
            TaskLog.add_log(task_id, "INFO", f"Xray监听启动成功，端口: {port}")
            return port

        except Exception as e:
            if process is not None:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except Exception as e_term:
                    logger.error(f"终止进程失败: {e_term}")
            self.port_pool.release(task_id)
            raise InternalServerError(f"Xray服务启动失败: {str(e)}")

    def stop_scan(self, task_id):
        """停止扫描并释放资源"""
        try:
            task_key = f"xray_task_{task_id}"
            task_data = redis_client.get(task_key)
            
            if not task_data:
                logger.warning(f"[Xray] 停止失败: 任务{task_id}未注册")
                return

            task_info = json.loads(task_data)
            pid = task_info["pid"]
            port = task_info["port"]
            try:
                main_proc = psutil.Process(pid)
                children = main_proc.children(recursive=True)
                for child in children:
                    try:
                        child.kill()
                        logger.debug(f"已kill子进程 {child.pid}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        logger.debug(f"子进程{child.pid}已终止或无权限: {str(e)}")
                        continue
                main_proc.kill()
                logger.debug(f"已kill主进程 {pid}")
            except psutil.NoSuchProcess:
                logger.info(f"进程{pid}已不存在")

            # 确保进程已退出
            if self._is_process_running(pid):
                logger.error(f"进程{pid}终止失败！")
                raise RuntimeError("无法终止Xray进程")

            # 解析剩余数据
            self.parse_results(task_id)

            # 释放资源
            self.port_pool.release(task_id)
            redis_client.delete(task_key)            
        except Exception as e:
            logger.error(f"[Xray] 停止异常: {str(e)}", exc_info=True)
            raise InternalServerError(f"停止扫描失败: {str(e)}")

    def parse_results(self, task_id):
        with self.parse_lock:
            try:
                task_data = redis_client.get(f"xray_task_{task_id}")
                if not task_data:
                    return False
                    
                task_info = json.loads(task_data)
                output_file = task_info["output"]
                start_pos = task_info.get("parsed_positions", 0)
                
                vul_list = []
                with open(output_file, "r", encoding="utf-8") as f:
                    f.seek(start_pos)
                    raw_data = f.read().strip()
                    
                    # 修复1：处理可能的未闭合JSON数组结构
                    if raw_data.startswith("["):
                        raw_data = raw_data[1:]  # 移除开头的[
                    if raw_data.endswith("]"):
                        raw_data = raw_data[:-1]  # 移除结尾的]
                    
                    # 修复2：分割有效JSON对象（兼容末尾逗号）
                    lines = []
                    for line in raw_data.splitlines():
                        line = line.strip()
                        if line in ("", "[", "]", ","):
                            continue
                        if line.endswith(","):
                            line = line[:-1]
                        lines.append(line)
                    
                    # 逐行解析
                    for line in lines:
                        try:
                            data = json.loads(line)
                            vul = self._parse_vulnerability(data, task_id)
                            if vul:
                                vul_list.append(vul)
                        except json.JSONDecodeError as e:
                            logger.error(f"[{task_id}] 行解析失败: {str(e)}\n行内容: {line}")
                            continue
                    
                    # 更新解析位置
                    new_pos = f.tell()
                    redis_client.set(f"xray_task_{task_id}", json.dumps({
                        **task_info,
                        "parsed_positions": new_pos
                    }))

                if vul_list:
                    VulService._save_results(task_id, vul_list)
                    logger.info(f"[Xray] 任务{task_id}新增{len(vul_list)}条漏洞")
                return True
                
            except Exception as e:
                logger.error(f"解析失败: {str(e)}", exc_info=True)
                return False

    def get_active_tasks(self):
        """获取所有活跃的Xray任务"""
        active_tasks = []
        for key in redis_client.keys("xray_task_*"):
            task_id = key.decode().split("_")[-1]
            task_data = redis_client.get(key)
            if task_data:
                task_info = json.loads(task_data)
                if task_info.get("status") == "running":
                    active_tasks.append(task_id)
        return active_tasks

    def _is_process_running(self, pid):
        """增强型进程状态检查"""
        try:
            process = psutil.Process(pid)
            return process.status() not in [
                psutil.STATUS_ZOMBIE, 
                psutil.STATUS_DEAD
            ]
        except psutil.NoSuchProcess:
            return False
        except psutil.AccessDenied:
            logger.error(f"无权限访问进程{pid}")
            return True  # 假设进程仍在运行
        except Exception as e:
            logger.error(f"进程检查异常: {str(e)}")
            return True  # 保守处理

    def _parse_vulnerability(self, vuln, task_id):
        """解析单个漏洞数据"""
        try:
            scan_id = f"xray_{task_id}_{vuln['create_time']}_{randint(1, 9999)}"
            new_vuln = Vulnerability(
                task_id=task_id,
                scan_source="XRAY",
                scan_id=scan_id,
                vul_type=vuln['plugin'],
                severity=vuln.get('extra', {}).get('level', 'info').lower()  # 优先使用extra中的level
            )
            new_vuln.time = datetime.fromtimestamp(
                vuln['create_time'] / 1000, 
                tz=timezone.utc  # 使用UTC时区
            )
            detail = vuln.get('detail', {})
            snapshot = "\n\n".join(
                [f"Request:\n{req}\nResponse:\n{resp}" 
                for req, resp in detail.get('snapshot', [])]
            )
            
            new_vuln.details = json.dumps({
                'target': vuln['target']['url'],
                'payload': detail.get('payload', ''),
                'snapshot': snapshot,
                'extra': vuln.get('extra', {})
            }, ensure_ascii=False)

            # 自动生成描述和建议（根据插件类型）
            plugin_type = vuln['plugin'].split('/')[0]
            description_map = {
                'dirscan': '敏感目录泄露',
                'poc-yaml': '已知漏洞利用',
                'sqldet': 'SQL注入漏洞'
            }
            new_vuln.description = f"{description_map.get(plugin_type, '安全风险')} @ {vuln['target']['url']}"

            # 解决方案模板
            solution_template = {
                'dirscan': '建议删除不必要的敏感文件',
                'poc-yaml': '请及时升级相关组件',
                'sqldet': '使用参数化查询防止注入'
            }
            new_vuln.solution = solution_template.get(plugin_type, '请参考安全最佳实践进行修复')

            return new_vuln
        except Exception as e:
            logger.warning(f"漏洞数据解析异常: {str(e)}")
            return None