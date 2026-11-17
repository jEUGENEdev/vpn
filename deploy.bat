@echo off
setlocal DisableDelayedExpansion
where wsl.exe >nul 2>&1
if errorlevel 1 (
  echo WSL is required. Run in an Administrator terminal:
  echo   wsl --install -d Ubuntu-24.04
  echo Then open Ubuntu once, create its Linux user, and install Python 3.12+ and Go 1.27.4+.
  set "LINEVPN_DEPLOY_EXIT=1"
  goto finish
)
rem WSLENV translates the repository path, including spaces, without shell interpolation.
set "LINEVPN_DEPLOY_WINDOWS_ROOT=%~dp0"
if defined WSLENV (
  set "WSLENV=%WSLENV%:LINEVPN_DEPLOY_WINDOWS_ROOT/p"
) else (
  set "WSLENV=LINEVPN_DEPLOY_WINDOWS_ROOT/p"
)
if defined LINEVPN_WSL_DISTRO (
  wsl.exe --distribution "%LINEVPN_WSL_DISTRO%" --exec bash -lc "exec bash \"${LINEVPN_DEPLOY_WINDOWS_ROOT}/deploy.sh\""
) else (
  wsl.exe --exec bash -lc "exec bash \"${LINEVPN_DEPLOY_WINDOWS_ROOT}/deploy.sh\""
)
set "LINEVPN_DEPLOY_EXIT=%ERRORLEVEL%"
if not "%LINEVPN_DEPLOY_EXIT%"=="0" echo Deployment failed. See the error above. Check that the selected WSL distribution is installed and initialized.
:finish
if not defined LINEVPN_NO_PAUSE pause
exit /b %LINEVPN_DEPLOY_EXIT%
