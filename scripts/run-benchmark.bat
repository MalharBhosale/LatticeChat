@echo off
setlocal enabledelayedexpansion
title LatticeChat - Post-Quantum Cryptography Benchmark Runner

echo =====================================================================
echo   LatticeChat Cryptographic Benchmark Suite (FIPS 203 / FIPS 204)
echo =====================================================================

where java >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Java is not found on PATH. Please install Java 21 LTS or later.
    pause
    exit /b 1
)

where mvn >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Apache Maven is not found on PATH. Please install Maven 3.8+.
    pause
    exit /b 1
)

set "ARGS=%*"
if "%ARGS%"=="" (
    set "ARGS=--export-file docs/BENCHMARK_RESULTS.md"
    echo [INFO] No arguments specified. Running default suite and exporting to docs/BENCHMARK_RESULTS.md
)

echo [INFO] Executing PqcBenchmarkRunner with parameters: !ARGS!
mvn exec:java -pl secure-chat-common -Dexec.mainClass="com.securechat.common.crypto.benchmark.PqcBenchmarkRunner" -Dexec.args="!ARGS!"

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Benchmark execution failed with exit code %ERRORLEVEL%
    pause
) else (
    echo [SUCCESS] Benchmarking completed.
)
