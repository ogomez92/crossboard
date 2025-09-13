@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM Simple Windows build helper for crossboard
REM Usage:
REM   makefile.bat build
REM   makefile.bat build-os-arch <goos> <goarch>
REM   makefile.bat clean

if not defined DIST set "DIST=dist"
if not defined BIN set "BIN=crossboard"
if not defined PKG set "PKG=./cmd/crossboard"

if "%~1"=="" goto :help
if /I "%~1"=="build" goto :build
if /I "%~1"=="build-os-arch" goto :buildosarch
if /I "%~1"=="clean" goto :clean
goto :help

:build
if not exist "%DIST%" mkdir "%DIST%" >nul 2>&1
set "OUT=%DIST%\%BIN%.exe"
echo Building %OUT% ...
go build %GOFLAGS% -o "%OUT%" "%PKG%"
if errorlevel 1 (
  echo Build failed.
  exit /b 1
) else (
  echo Built %OUT%
)
exit /b 0

:buildosarch
set "GOOS=%~2"
set "GOARCH=%~3"
if not defined GOOS set "GOOS=%OS%"
if not defined GOARCH set "GOARCH=%ARCH%"
if not defined GOOS goto :usage_osarch
if not defined GOARCH goto :usage_osarch
if not exist "%DIST%" mkdir "%DIST%" >nul 2>&1
set "OUT=%DIST%\%BIN%-%GOOS%-%GOARCH%"
if /I "%GOOS%"=="windows" set "OUT=%OUT%.exe"
echo Building %OUT% (GOOS=%GOOS% GOARCH=%GOARCH%) ...
set "_OLD_GOOS=%GOOS%"
set "_OLD_GOARCH=%GOARCH%"
REM Use temporary env for this process
set GOOS=%GOOS%
set GOARCH=%GOARCH%
go build %GOFLAGS% -o "%OUT%" "%PKG%"
set GOOS=%_OLD_GOOS%
set GOARCH=%_OLD_GOARCH%
if errorlevel 1 (
  echo Cross build failed.
  exit /b 1
) else (
  echo Built %OUT%
)
exit /b 0

:clean
if exist "%DIST%" (
  echo Removing %DIST% ...
  rmdir /S /Q "%DIST%"
)
exit /b 0

:usage_osarch
echo Usage: %~nx0 build-os-arch ^<goos^> ^<goarch^>
echo Example: %~nx0 build-os-arch linux amd64
exit /b 2

:help
echo Usage:
echo   %~nx0 build
echo   %~nx0 build-os-arch ^<goos^> ^<goarch^>
echo   %~nx0 clean
exit /b 2
