#!/usr/bin/env bash
# ==============================================================================
# LatticeChat Master Test Suite Runner (Linux / macOS)
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================================================${NC}"
echo -e "${BLUE}  LatticeChat Comprehensive Test Suite Runner                        ${NC}"
echo -e "${BLUE}  Post-Quantum End-to-End Cryptographic Messaging                    ${NC}"
echo -e "${BLUE}  [FIPS 203 ML-KEM-768 | FIPS 204 ML-DSA-65 | AES-256-GCM]           ${NC}"
echo -e "${BLUE}=====================================================================${NC}"

# Check Java installation
if ! command -v java &> /dev/null; then
    echo -e "${RED}[ERROR] java command not found. Please install OpenJDK 21 LTS or later.${NC}"
    exit 1
fi

JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f1)
echo -e "${GREEN}[INFO] Detected Java major version: ${JAVA_VERSION}${NC}"

if [ "$JAVA_VERSION" -lt 21 ]; then
    echo -e "${YELLOW}[WARNING] Java 21 LTS or higher is recommended. Detected: ${JAVA_VERSION}${NC}"
fi

# Check Maven installation
if ! command -v mvn &> /dev/null; then
    echo -e "${RED}[ERROR] mvn command not found. Please install Apache Maven 3.8+.${NC}"
    exit 1
fi

echo -e "${GREEN}[INFO] Executing comprehensive test suite across all modules...${NC}"
echo -e "${GREEN}[INFO] Modules: secure-chat-common, secure-chat-server, secure-chat-client${NC}"
echo -e "${BLUE}=====================================================================${NC}"

if mvn test "$@"; then
    echo ""
    echo -e "${GREEN}=====================================================================${NC}"
    echo -e "${GREEN}[SUCCESS] All test suites passed successfully! (100% green)          ${NC}"
    echo -e "${GREEN}=====================================================================${NC}"
    exit 0
else
    EXIT_CODE=$?
    echo ""
    echo -e "${RED}=====================================================================${NC}"
    echo -e "${RED}[ERROR] One or more test suites FAILED with exit code ${EXIT_CODE}   ${NC}"
    echo -e "${RED}=====================================================================${NC}"
    exit ${EXIT_CODE}
fi
