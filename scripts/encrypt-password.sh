#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/scripts/java-env.sh"

if [ "$#" -gt 1 ]; then
  echo "Usage: $0 [plain-password]" >&2
  exit 2
fi

load_f5_master_key "${ROOT_DIR}/config/.F5_MASTER_KEY"

MAIN_CLASSES="$("${ROOT_DIR}/scripts/compile-java.sh")"
LIB_CP="${ROOT_DIR}/lib/*"
if [ "$#" -eq 1 ]; then
  "$JAVA_CMD" -cp "$(java_classpath "$MAIN_CLASSES:$LIB_CP")" org.qypp.Main encrypt-password "$1"
else
  "$JAVA_CMD" -cp "$(java_classpath "$MAIN_CLASSES:$LIB_CP")" org.qypp.Main encrypt-password
fi
