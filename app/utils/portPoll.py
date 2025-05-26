import threading
import socket
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class PortPoolMeta(type):
    """线程安全单例元类"""
    _instances = {}
    _lock = threading.Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

class PortPool(metaclass=PortPoolMeta):
    """增强型端口池管理"""
    def __init__(self, start_port: Optional[int] = None, end_port: Optional[int] = None):
        if not hasattr(self, 'initialized'):
            self.lock = threading.RLock()  # 可重入锁
            self.allocated = {}  # {task_id: port}
            self.port_range = ()
            
            if start_port and end_port:
                self.initialize_port_range(start_port, end_port)
                
            self.initialized = True

    def initialize_port_range(self, start_port: int, end_port: int) -> None:
        """初始化端口范围"""
        with self.lock:
            if self.port_range:
                raise RuntimeError("Port range already initialized")
            if end_port < start_port:
                raise ValueError("Invalid port range")
                
            self.port_range = (start_port, end_port)
            logger.info(f"Port pool initialized: {self.port_range}")

    def allocate(self, task_id: str) -> int:
        """安全分配端口"""
        with self.lock:
            if not self.port_range:
                raise RuntimeError("Port range not initialized")

            # 遍历整个端口范围（含状态检查）
            for port in range(*self.port_range):
                if self._is_port_available(port) and (port not in self.allocated.values()):
                    self.allocated[task_id] = port
                    logger.debug(f"Allocated port {port} for task {task_id}")
                    return port
                    
            # 尝试回收已释放但被占用的端口
            for task_id, port in list(self.allocated.items()):
                if not self._is_port_available(port):
                    self._force_release(task_id)
                    
            raise RuntimeError("No available ports")

    def release(self, task_id: str) -> bool:
        """安全释放端口"""
        with self.lock:
            port = self.allocated.pop(task_id, None)
            if port is None:
                return False
                
            # 验证端口是否真正释放
            if not self._is_port_available(port):
                logger.warning(f"Port {port} still in use after release!")
                return False
                
            logger.debug(f"Released port {port} from task {task_id}")
            return True

    def _force_release(self, task_id: str) -> None:
        """强制释放异常端口"""
        port = self.allocated.pop(task_id, None)
        if port:
            logger.error(f"Force releasing port {port} due to occupation")

    def _is_port_available(self, port: int) -> bool:
        """准确检测端口可用性"""
        try:
            # 尝试绑定到所有接口
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                s.close()
                return True
        except OSError:
            return False

    def get_status(self) -> dict:
        """获取端口池状态"""
        with self.lock:
            return {
                "total": self.port_range[1] - self.port_range[0] + 1,
                "allocated": len(self.allocated),
                "available": self.port_range[1] - self.port_range[0] + 1 - len(self.allocated)
            }