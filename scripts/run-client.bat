@echo off
setlocal enabledelayedexpansion
title LatticeChat Desktop Client - Post-Quantum Messenger

echo =====================================================================
echo   LatticeChat Desktop Client (JavaFX 21 + NIST PQC Keystore)
echo =====================================================================

where java >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Java is not found on PATH. Please install Java 21 LTS or later.
    pause
    exit /b 1
)

:: Locate client Fat JAR
set "JAR_PATH=secure-chat-client\target\lattice-chat-client.jar"
if not exist "%JAR_PATH%" (
    set "JAR_PATH=..\secure-chat-client\target\lattice-chat-client.jar"
)

if exist "%JAR_PATH%" (
    echo [INFO] Launching standalone JavaFX client JAR: %JAR_PATH%
    java -jar "%JAR_PATH%" %*
) else (
    echo [INFO] Client Fat JAR not found. Launching via Maven javafx:run...
    mvn javafx:run -pl secure-chat-client %*
)

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Client exited with code %ERRORLEVEL%
    pause
)
