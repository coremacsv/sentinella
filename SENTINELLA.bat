@echo off
title Sentinella - sicurezza e salute del tuo PC
cd /d "%~dp0"

if not exist "%~dp0sentinella.ps1" (
    echo.
    echo   ERRORE: manca il file sentinella.ps1
    echo   Deve trovarsi nella stessa cartella di questo file.
    echo.
    pause
    exit /b 1
)

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo   Sentinella ha bisogno dei permessi di amministratore per
    echo   esaminare antivirus, servizi e stato dei dischi.
    echo   Conferma la finestra di Windows che sta per aprirsi...
    echo.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

rem La schermata iniziale a blocchi ha bisogno di larghezza: senza questo
rem su una finestra da 80 colonne il titolo andrebbe a capo e si sfalderebbe.
mode con: cols=100 lines=45 >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sentinella.ps1"
