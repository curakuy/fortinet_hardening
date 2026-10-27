@echo off
chcp 65001 >nul
title SW-02 // FortiOS 7.4 ve 7.6 Hardening Analiz Motoru (yukaruc.tech)
cd /d "%~dp0"
echo ============================================================================
echo [SW-02] FortiOS 7.4 ve 7.6 Hardening, Zafiyet ve NPU Analiz Motoru Baslatiliyor...
echo ============================================================================
if not exist "node_modules\ssh2" (
    echo [BILGI] Ilk calistirma: SSH baglanti modulu (ssh2) yukleniyor, lutfen bekleyin...
    call npm install --no-audit --no-fund
)
echo Tarayicinizda http://localhost:8788 acilacaktir.
start "" "http://localhost:8788"
node server-local.mjs
pause
