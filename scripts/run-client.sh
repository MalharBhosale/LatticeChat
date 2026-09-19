#!/usr/bin/env bash
# ==============================================================================
# LatticeChat Desktop Client Launcher (Linux / macOS)
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=====================================================================${NC}"
echo -e "${BLUE}  LatticeChat Desktop Client (JavaFX 21 + NIST PQC Keystore)        ${NC}"
echo -e "${BLUE}=====================================================================${NC}"

if ! command -v java &> /dev/null; then
    echo -e "${RED}[ERROR] java command not found. Please install OpenJDK 21 LTS or later.${NC}"
    exit 1
fi

JAR_PATH="secure-chat-client/target/lattice-chat-client.jar"
if [ ! -f "$JAR_PATH" ]; then
    JAR_PATH="../secure-chat-client/target/lattice-chat-client.jar"
fi

if [ -f "$JAR_PATH" ]; then
    echo -e "${GREEN}[INFO] Launching standalone JavaFX client JAR: ${JAR_PATH}${NC}"
    exec java -jar "$JAR_PATH" "$@"
else
    echo -e "${YELLOW}[INFO] Standalone client JAR not found. Launching via Maven javafx:run...${NC}"
    exec mvn javafx:run -pl secure-chat-client "$@"
fi
