@echo off
chcp 65001 >nul
cd /d %~dp0backend

echo ============================================
echo  金融企业级 RAG 知识库 - 后端服务
echo ============================================

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] 创建虚拟环境...
    python -m venv .venv
)

echo [2/3] 安装 / 校验依赖...
".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -r requirements.txt

echo.
echo --------------------------------------------
echo  服务地址: http://127.0.0.1:8000
echo  接口文档: http://127.0.0.1:8000/docs
echo  默认账号: admin / Admin@123
echo --------------------------------------------
echo.

REM 不内置 EMBED_REQUIRE_API_KEY=false 放行：放行后没有向量可用（检索全 503），
REM "能起却不可用"比明确报错更糟。未配置 EMBED_API_KEY 时按方案 B 明确拒绝启动
REM ——请先在 .env 配好 DATABASE_URL 与 EMBED_API_KEY 再跑本脚本。
REM 仅离线测试/回归基线可显式放行（EMBED_REQUIRE_API_KEY=false）。

".venv\Scripts\python.exe" run.py --port 8000
pause
