@echo off
title Sentinella - crea collegamento sul Desktop
cd /d "%~dp0"

if not exist "%~dp0SENTINELLA.bat" (
    echo.
    echo   ERRORE: manca SENTINELLA.bat in questa cartella.
    echo.
    pause
    exit /b 1
)

echo.
echo   Creo un collegamento a Sentinella sul tuo Desktop,
echo   con l'icona dello scudo.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s = (New-Object -ComObject WScript.Shell); $d = [Environment]::GetFolderPath('Desktop');" ^
  "$l = $s.CreateShortcut((Join-Path $d 'Sentinella.lnk'));" ^
  "$l.TargetPath = '%~dp0SENTINELLA.bat';" ^
  "$l.WorkingDirectory = '%~dp0';" ^
  "$l.Description = 'Sentinella - sicurezza e salute del tuo PC';" ^
  "if (Test-Path '%~dp0sentinella.ico') { $l.IconLocation = '%~dp0sentinella.ico' };" ^
  "$l.Save();" ^
  "Write-Host ''; Write-Host '  Fatto: trovi Sentinella sul Desktop.' -ForegroundColor Green"

echo.
pause
