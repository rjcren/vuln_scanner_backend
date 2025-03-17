# 基础镜像
FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    wkhtmltopdf \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    wkhtmltopdf \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目代码
COPY . .

# 设置环境变量
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# 确保容器用户可写
RUN mkdir /app/logs && chmod 777 /app/logs

# 启动命令
CMD ["gunicorn", "--bind", "0.0.0.0:443", "--workers", "4", "run:app"]

