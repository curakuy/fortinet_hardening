@echo off
setlocal
title FortiOS 7.4 / 7.6 Hardening Analiz Motoru - yukaruc.tech
cd /d "%~dp0"

echo ============================================================================
echo  FortiOS 7.4 ve 7.6 Hardening, Zafiyet ve Yukseltme Analiz Motoru
echo ============================================================================

where node >nul 2>nul
if errorlevel 1 goto NONODE

for /f "tokens=1 delims=." %%v in ('node -p "process.versions.node"') do set NODEMAJOR=%%v
if %NODEMAJOR% LSS 18 goto OLDNODE

if not exist "PUBLIC_ASSETS\index.html" goto NOASSETS
if not exist "_worker.js" goto NOWORKER

if exist "node_modules\ssh2\package.json" goto RUN
echo [BILGI] Ilk calistirma: ssh2 SSH modulu yukleniyor, lutfen bekleyin...
call npm install --no-audit --no-fund --ignore-scripts
if errorlevel 1 goto NPMFAIL

:RUN
echo Tarayicinizda http://localhost:8788 acilacaktir. Kapatmak icin bu pencereyi kapatin.
start "" "http://localhost:8788"
node server-local.mjs
pause
exit /b 0

:NONODE
echo [HATA] Node.js bulunamadi. Lutfen https://nodejs.org adresinden Node.js 18 veya ustu LTS surumunu kurun,
echo        kurulumdan sonra bu pencereyi kapatip BASLAT.bat dosyasini tekrar calistirin.
pause
exit /b 1

:OLDNODE
echo [HATA] Node.js surumunuz cok eski: %NODEMAJOR%. En az Node.js 18 gereklidir. https://nodejs.org
pause
exit /b 1

:NOASSETS
echo [HATA] PUBLIC_ASSETS\index.html bulunamadi. Depoyu eksiksiz indirdiginizden emin olun.
pause
exit /b 1

:NOWORKER
echo [HATA] _worker.js bulunamadi. Depoyu eksiksiz indirdiginizden emin olun.
pause
exit /b 1

:NPMFAIL
echo [HATA] npm install basarisiz oldu. Internet baglantinizi veya proxy ayarlarinizi kontrol edip tekrar deneyin.
echo        Elle kurulum: bu klasorde komut satiri acip "npm install" calistirin.
pause
exit /b 1
