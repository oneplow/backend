@echo off
REM ============================================================
REM  Starts the Tor daemon bundled with Tor Browser as a plain
REM  proxy (no browser needed). SOCKS on 9050, control on 9051
REM  with cookie auth. Leave this window OPEN while you run easy-ai.
REM  Run this from the easy-ai\ folder so tor_data lands beside it.
REM ============================================================

set "TOR_EXE=C:\Users\Emir\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe"
set "DATA=%~dp0tor_data"

if not exist "%TOR_EXE%" (
  echo [!] tor.exe not found at:
  echo     "%TOR_EXE%"
  echo     Fix TOR_EXE in start_tor.bat
  pause
  exit /b 1
)

if not exist "%DATA%" mkdir "%DATA%"

echo Starting Tor  ^|  SOCKS 127.0.0.1:9050  ^|  Control 127.0.0.1:9051
echo Wait for "Bootstrapped 100%% (done)" then leave this window open.
echo.
"%TOR_EXE%" --SocksPort 9050 --ControlPort 9051 --CookieAuthentication 1 --DataDirectory "%DATA%"

echo.
echo [!] Tor exited. See messages above.
pause
