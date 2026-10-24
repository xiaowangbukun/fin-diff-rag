@echo off
chcp 65001 >nul
cd /d %~dp0frontend

echo ============================================
echo  金融企业级 RAG 知识库 - 前端控制台
echo ============================================

if not exist "node_modules" (
    echo [1/2] 安装依赖（首次较慢）...
    call npm install --no-audit --no-fund
)

echo [2/2] 启动开发服务器 http://127.0.0.1:5173
call npm run dev
pause
