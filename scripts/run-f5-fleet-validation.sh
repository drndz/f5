#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/scripts/java-env.sh"

TARGETS_FILE="${1:-${ROOT_DIR}/config/f5-targets.csv}"
LOCAL_OUTPUT_DIR="${2:-${ROOT_DIR}/f5-validation-results}"

load_f5_master_key "${ROOT_DIR}/config/.F5_MASTER_KEY"

if [ ! -f "$TARGETS_FILE" ]; then
  echo "Targets file not found: $TARGETS_FILE" >&2
  exit 2
fi

mkdir -p "$LOCAL_OUTPUT_DIR"
MAIN_CLASSES="$("${ROOT_DIR}/scripts/compile-java.sh")"
LIB_CP="${ROOT_DIR}/lib/*"

"$JAVA_CMD" -cp "$(java_classpath "$MAIN_CLASSES:$LIB_CP")" org.qypp.Main fleet "$TARGETS_FILE" "$LOCAL_OUTPUT_DIR"
