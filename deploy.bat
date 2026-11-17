@echo off
setlocal DisableDelayedExpansion
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\deploy-windows.ps1"
set "LINEVPN_DEPLOY_EXIT=%ERRORLEVEL%"
if not "%LINEVPN_DEPLOY_EXIT%"=="0" echo Deployment failed. See the error above.
if not defined LINEVPN_NO_PAUSE pause
exit /b %LINEVPN_DEPLOY_EXIT%
