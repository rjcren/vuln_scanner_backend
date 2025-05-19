#!/bin/bash

# 模型下载配置
MODEL_NAME="paraphrase-multilingual-MiniLM-L12-v2"
CACHE_DIR="${1:-/opt/models/sentence-transformers}"
# 可切换的镜像源（取消注释要使用的镜像）
# HUGGINGFACE_URL="https://huggingface.co/sentence-transformers/$MODEL_NAME/resolve/main"  # 官方源
HUGGINGFACE_URL="https://hf-mirror.com/sentence-transformers/$MODEL_NAME/resolve/main"  # 清华镜像
# HUGGINGFACE_URL="https://mirror.baai.ac.cn/models/$MODEL_NAME/resolve/main"  # BAAI镜像

# 代理配置（如果需要）
# PROXY="--proxy=http://proxy.example.com:8080"
PROXY=""

# 模型文件列表
FILES=(
  "config.json"
  "pytorch_model.bin"
  "sentence_bert_config.json"
  "special_tokens_map.json"
  "tokenizer_config.json"
  "vocab.txt"
)

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # 恢复默认颜色

# 检查依赖
check_dependency() {
  command -v $1 >/dev/null 2>&1 || { echo -e "${RED}错误: 需要安装$1${NC}"; exit 1; }
}

# 下载单个文件
download_file() {
  local file=$1
  local url="$HUGGINGFACE_URL/$file"
  local target="$CACHE_DIR/$file"
  
  echo -e "${YELLOW}正在下载: $file${NC}"
  
  # 断点续传下载
  if [ -f "$target" ]; then
    echo -e "${YELLOW}发现部分下载文件，尝试断点续传...${NC}"
    wget $PROXY -c -q --show-progress "$url" -O "$target.tmp"
    if [ $? -eq 0 ]; then
      mv "$target.tmp" "$target"
      echo -e "${GREEN}√ $file 下载完成（断点续传）${NC}"
    else
      echo -e "${RED}× $file 下载失败${NC}"
      return 1
    fi
  else
    wget $PROXY -q --show-progress "$url" -O "$target"
    if [ $? -eq 0 ]; then
      echo -e "${GREEN}√ $file 下载完成${NC}"
    else
      echo -e "${RED}× $file 下载失败${NC}"
      return 1
    fi
  fi
}

# 创建目录（可选使用sudo）
create_directory() {
  if [ ! -d "$CACHE_DIR" ]; then
    echo -e "${YELLOW}创建目录: $CACHE_DIR${NC}"
    if [ "$(id -u)" -eq 0 ]; then
      mkdir -p "$CACHE_DIR"
    else
      sudo mkdir -p "$CACHE_DIR"
    fi
    
    if [ $? -ne 0 ]; then
      echo -e "${RED}错误: 无法创建目录 $CACHE_DIR${NC}"
      exit 1
    fi
  fi
}

# 设置文件权限（可选使用sudo）
set_permissions() {
  if [ "$(id -u)" -eq 0 ]; then
    chmod -R 755 "$CACHE_DIR"
  else
    sudo chmod -R 755 "$CACHE_DIR"
  fi
}

# 主函数
main() {
  # 检查依赖
  check_dependency wget
  
  # 创建目录
  create_directory
  
  # 下载所有文件
  local success=true
  for file in "${FILES[@]}"; do
    download_file "$file" || success=false
  done
  
  # 设置权限
  set_permissions
  
  # 检查是否所有文件都下载成功
  if $success; then
    echo -e "${GREEN}===== 模型 $MODEL_NAME 下载完成 ====${NC}"
    echo -e "${GREEN}模型路径: $CACHE_DIR${NC}"
    echo -e "${GREEN}使用的镜像: ${HUGGINGFACE_URL%/*}${NC}"
  else
    echo -e "${RED}===== 部分文件下载失败，请检查网络连接 ====${NC}"
    exit 1
  fi
}

# 执行主函数
main