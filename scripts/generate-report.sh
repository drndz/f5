#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/scripts/java-env.sh"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <json-input-dir> [output-report.md]" >&2
  exit 2
fi

INPUT_DIR="$1"
REPORT_TIMESTAMP="$(date -u +"%Y-%m-%dT%H%M%SZ")"
OUTPUT_FILE="${2:-validation-report-${REPORT_TIMESTAMP}.md}"
MAIN_CLASSES="$("${ROOT_DIR}/scripts/compile-java.sh")"
LIB_CP="${ROOT_DIR}/lib/*"

"$JAVA_CMD" -cp "$(java_classpath "$MAIN_CLASSES:$LIB_CP")" org.qypp.Main report --input-dir "$INPUT_DIR" --output "$OUTPUT_FILE"
