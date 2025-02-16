# 项目目录
graduation-project/
├── app/                           # 应用核心代码
│   ├── __init__.py               # 应用工厂函数，初始化Flask实例
│   ├── config.py
│   │
│   ├── models/                   # 数据模型定义
│   │   ├── __init__.py           # 导出所有模型类
│   │   ├── user.py               # 用户模型（含RBAC权限）
│   │   ├── task.py               # 扫描任务模型
│   │   ├── vulnerability.py      # 漏洞详情模型
│   │   └── threat_intel.py       # 威胁情报模型
│   │
│   ├── routes/                   # API路由定义
│   │   ├── __init__.py           # 路由包标识（空文件）
│   │   ├── auth.py               # 用户认证相关路由
│   │   ├── tasks.py              # 扫描任务管理路由
│   │
│   ├── services/                 # 业务逻辑服务层
│   │   ├── __init__.py           # 导出服务类
│   │   ├── auth.py               # 用户认证服务
│   │   ├── scanner.py            # 漏洞扫描引擎服务
│   │   └── threat_intel.py       # 威胁情报同步服务
│   │
│   ├── tasks/                    # Celery异步任务
│   │   ├── __init__.py           # Celery实例初始化
│   │   ├── scan_tasks.py         # 扫描任务执行逻辑
│   │   └── periodic_tasks.py     # 定时任务配置
│   │
│   ├── utils/                    # 工具类与辅助模块
│   │   ├── __init__.py           # 导出工具函数
│   │   ├── security.py           # 安全工具（密码哈希/JWT操作）
│   │   ├── scanner.py            # 扫描工具封装（Nmap/ZAP集成）
│   │   └── exceptions.py         # 自定义异常体系
│   │
│   ├── extensions.py             # 扩展对象初始化（数据库/Celery）
│   └── static/                   # 静态资源
│       └── templates/            # 报告模板文件（HTML/PDF）
│
├── migrations/                   # 数据库迁移脚本（由Flask-Migrate生成）
│
├── tests/                        # 测试模块
│   ├── __init__.py               # 测试包标识
│   ├── unit/                     # 单元测试
│   └── integration/              # 集成测试
│
├── docker/                       # Docker相关配置（可选）
│   ├── nginx/                    # Nginx反向代理配置
│   └── celery/                   # Celery Worker配置
│
├── logs/                         # 应用日志存储目录（自动生成）
│
├── requirements.txt              # Python依赖清单
├── docker-compose.yml            # 多容器编排配置（MySQL+Redis+App）
├── Dockerfile                    # 应用镜像构建文件
├── .env.example                  # 环境变量模板文件
└── run.py                        # 应用启动入口