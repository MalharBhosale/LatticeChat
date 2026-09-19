@echo off
setlocal enabledelayedexpansion
title LatticeChat Server - Post-Quantum Secure Messaging

echo =====================================================================
echo   LatticeChat Server Launcher (Spring Boot 3 + NIST PQC Engine)
echo =====================================================================

:: Verify Java installation
where java >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Java is not found on PATH. Please install Java 21 LTS or later.
    pause
    exit /b 1
)

:: Check Java version
for /f tokens^=2-5^ delims^=.-_+^" %%j in ('java -fullversion 2^>^&1') do set "JAVA_VER=%%j"
if "%JAVA_VER%"=="" (
    for /f tokens^=3^ delims^=.-_+^" %%j in ('java -version 2^>^&1') do (
        set "JAVA_VER=%%j"
        goto :check_ver
    )
)

:check_ver
echo [INFO] Detected Java major version: %JAVA_VER%
if %JAVA_VER% LSS 21 (
    echo [WARNING] Java 21 or higher is strongly recommended. Current version: %JAVA_VER%
)

:: Locate executable JAR
set "JAR_PATH=secure-chat-server\target\lattice-chat-server.jar"
if not exist "%JAR_PATH%" (
    set "JAR_PATH=..\secure-chat-server\target\lattice-chat-server.jar"
)

if exist "%JAR_PATH%" (
    echo [INFO] Starting compiled server artifact: %JAR_PATH%
    java -jar "%JAR_PATH%" %*
) else (
    echo [INFO] Server JAR not found. Launching via Maven spring-boot:run...
    mvn spring-boot:run -pl secure-chat-server %*
)

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Server exited with error code %ERRORLEVEL%
    pause
)
