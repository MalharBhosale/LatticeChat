#!/usr/bin/env bash
# ==============================================================================
# LatticeChat Post-Quantum Cryptography Benchmark Launcher (Linux / macOS)
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=====================================================================${NC}"
echo -e "${BLUE}  LatticeChat Cryptographic Benchmark Suite (FIPS 203 / FIPS 204)    ${NC}"
echo -e "${BLUE}=====================================================================${NC}"

if ! command -v java &> /dev/null; then
    echo -e "${RED}[ERROR] java command not found. Please install OpenJDK 21 LTS or later.${NC}"
    exit 1
fi

if ! command -v mvn &> /dev/null; then
    echo -e "${RED}[ERROR] mvn command not found. Please install Apache Maven 3.8+.${NC}"
    exit 1
fi

ARGS="$@"
if [ -z "$ARGS" ]; then
    ARGS="--export-file docs/BENCHMARK_RESULTS.md"
    echo -e "${YELLOW}[INFO] No arguments specified. Running default suite and exporting to docs/BENCHMARK_RESULTS.md${NC}"
fi

echo -e "${GREEN}[INFO] Executing PqcBenchmarkRunner with arguments: ${ARGS}${NC}"
mvn exec:java -pl secure-chat-common \
    -Dexec.mainClass="com.securechat.common.crypto.benchmark.PqcBenchmarkRunner" \
    -Dexec.args="${ARGS}"

echo -e "${GREEN}[SUCCESS] Benchmarking completed successfully.${NC}"
