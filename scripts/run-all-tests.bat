@echo off
setlocal enabledelayedexpansion
title LatticeChat - Comprehensive Test Suite Runner

echo =====================================================================
echo   LatticeChat Comprehensive Test Suite Runner
echo   Post-Quantum End-to-End Cryptographic Messaging
echo   [FIPS 203 ML-KEM-768 ^| FIPS 204 ML-DSA-65 ^| AES-256-GCM]
echo =====================================================================

:: Verify Java installation
where java >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Java is not found on PATH. Please install Java 21 LTS or later.
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

:: Verify Maven installation
where mvn >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Apache Maven is not found on PATH. Please install Maven 3.8+.
    exit /b 1
)

echo [INFO] Executing comprehensive test suite across all modules...
echo [INFO] Modules: secure-chat-common, secure-chat-server, secure-chat-client
echo =====================================================================

mvn test %*

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo =====================================================================
    echo [ERROR] One or more test suites FAILED with exit code %ERRORLEVEL%
    echo =====================================================================
    exit /b %ERRORLEVEL%
) else (
    echo.
    echo =====================================================================
    echo [SUCCESS] All test suites passed successfully! (100%% green)
    echo =====================================================================
)
