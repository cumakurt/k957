@echo off
setlocal
set "ARCH=amd64"
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"
"%~dp0dist\k957-windows-%ARCH%.exe" wizard
pause
