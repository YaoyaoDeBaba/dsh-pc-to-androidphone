@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo.
echo ===== 大肥鱼远控 · 一键推送 =====
echo.

where git >nul 2>nul
if errorlevel 1 (
  echo [x] 没找到 git。
  echo     请先装一个：https://git-scm.com/download/win
  echo     装完关掉这个窗口，再双击我。
  pause
  exit /b 1
)

set REMOTE=https://github.com/YaoyaoDeBaba/dsh-pc-to-androidphone.git

if not exist ".git" (
  echo [*] 首次使用，初始化仓库...
  git init -b main >nul
  git remote add origin %REMOTE%
)

git remote set-url origin %REMOTE%

echo [*] 同步远端...
git fetch origin main
if errorlevel 1 (
  echo [!] 远端还没有 main 分支，将直接推送。
) else (
  git reset --mixed origin/main >nul
)

echo [*] 提交改动...
git add -A
git commit -m "auto: %date% %time%"

echo [*] 推送到 GitHub...
git push -u origin main
if errorlevel 1 (
  echo.
  echo [x] 推送失败，常见原因：
  echo     1^) 第一次推送需要登录：弹窗里选 "Sign in with your browser"
  echo     2^) 网络不稳，再双击一次即可
  pause
  exit /b 1
)

echo.
echo [OK] 推送成功！
echo      GitHub Actions 正在编译，大约 3~5 分钟。
echo      手机上打开 App 会自动提示新版本，点一下就能装。
echo.
pause
