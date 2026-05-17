#!/usr/bin/env bash
# VulnHunter 一键启动脚本
set -e

cd "$(dirname "$0")"

echo "============================================="
echo " VulnHunter — AI 漏洞挖掘 Agent"
echo "============================================="

# 检查 python
if ! command -v python3 &> /dev/null; then
    echo "✗ 未找到 python3，请先安装 Python 3.10+"
    exit 1
fi

# 检查 git
if ! command -v git &> /dev/null; then
    echo "✗ 未找到 git，请先安装 git（用于克隆仓库）"
    exit 1
fi

# 创建虚拟环境（如果不存在）
if [ ! -d ".venv" ]; then
    echo "→ 首次运行，创建 Python 虚拟环境..."
    python3 -m venv .venv
fi

# 激活虚拟环境
# shellcheck disable=SC1091
source .venv/bin/activate

# 安装依赖
echo "→ 安装 / 更新依赖..."
pip install -q --upgrade pip
pip install -q -r backend/requirements.txt

# 创建数据目录
mkdir -p data/repos

echo ""
echo "✓ 准备完毕"
echo "→ 启动服务，访问 http://localhost:8765"
echo "→ 按 Ctrl+C 停止"
echo ""

cd backend
exec python main.py
