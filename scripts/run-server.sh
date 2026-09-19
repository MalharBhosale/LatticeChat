#!/usr/bin/env bash
# ==============================================================================
# LatticeChat Server Launcher (Linux / macOS)
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================================================${NC}"
echo -e "${BLUE}  LatticeChat Server Launcher (Spring Boot 3 + NIST PQC Engine)     ${NC}"
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

# Locate executable JAR
JAR_PATH="secure-chat-server/target/lattice-chat-server.jar"
if [ ! -f "$JAR_PATH" ]; then
    JAR_PATH="../secure-chat-server/target/lattice-chat-server.jar"
fi

if [ -f "$JAR_PATH" ]; then
    echo -e "${GREEN}[INFO] Launching standalone JAR: ${JAR_PATH}${NC}"
    exec java -jar "$JAR_PATH" "$@"
else
    echo -e "${YELLOW}[INFO] Standalone JAR not found. Launching via Maven spring-boot:run...${NC}"
    exec mvn spring-boot:run -pl secure-chat-server "$@"
fi
