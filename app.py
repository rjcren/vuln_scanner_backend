import os
import sys
from dotenv import load_dotenv
from app import create_app

# 优先加载环境变量（覆盖实例配置）
load_dotenv(verbose=True, override=True)

def validate_ssl_certs(cert_path, key_path):
    """验证 SSL 证书文件是否存在"""
    if not os.path.isfile(cert_path):
        raise FileNotFoundError(f"SSL 证书文件不存在: {cert_path}")
    if not os.path.isfile(key_path):
        raise FileNotFoundError(f"SSL 私钥文件不存在: {key_path}")

# 显式设置环境类型（优先级: 环境变量 > 默认值）
env = os.getenv("FLASK_ENV", "production")

# 创建应用实例
app = create_app(name=env)

# 配置 SSL 证书路径
ssl_cert = os.path.join(app.instance_path, "cert.pem")
ssl_key = os.path.join(app.instance_path, "key.pem")

try:
    validate_ssl_certs(ssl_cert, ssl_key)
except FileNotFoundError as e:
    if env == "production":
        app.logger.error(str(e))
        sys.exit(1)
    else:
        # 开发环境允许缺失证书（自动生成或忽略）
        ssl_cert, ssl_key = None, None

# 运行配置
host = os.getenv("FLASK_HOST", "0.0.0.0")
port = int(os.getenv("FLASK_PORT", "5000"))
debug = app.config.get("DEBUG", False)

# 生产环境强制关闭调试模式
if env == "production":
    debug = False

app.run(
    host=host,
    port=port,
    debug=debug,
    ssl_context=(ssl_cert, ssl_key) if ssl_cert else None
)