#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/scripts/java-env.sh"

TARGETS_FILE=""
LOCAL_OUTPUT_DIR=""
DETAILS_SSH=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --yes|--approve-all)
      export SSH_APPROVE_ALL_COMMANDS=true
      shift
      ;;
    --log)
      export SSH_LOG_COMMAND_OUTPUT=true
      shift
      ;;
    --details-ssh)
      DETAILS_SSH=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--yes|--approve-all] [--log] [--details-ssh] [targets.csv] [output-dir]" >&2
      exit 0
      ;;
    *)
      if [ -z "$TARGETS_FILE" ]; then
        TARGETS_FILE="$1"
      elif [ -z "$LOCAL_OUTPUT_DIR" ]; then
        LOCAL_OUTPUT_DIR="$1"
      else
        echo "Unexpected argument: $1" >&2
        echo "Usage: $0 [--yes|--approve-all] [--log] [--details-ssh] [targets.csv] [output-dir]" >&2
        exit 2
      fi
      shift
      ;;
  esac
done

CONFIG_DIR="$(effective_config_dir)"
TARGETS_FILE="${TARGETS_FILE:-${CONFIG_DIR}/f5-targets.csv}"
LOCAL_OUTPUT_DIR="${LOCAL_OUTPUT_DIR:-${ROOT_DIR}/f5-validation-results}"

if [ ! -f "$TARGETS_FILE" ]; then
  echo "Targets file not found: $TARGETS_FILE" >&2
  exit 2
fi

if awk -F, '/^[[:space:]]*($|#)/ { next } $1 == "name" { next } { password=$4; sub(/^[[:space:]]+/, "", password); sub(/[[:space:]]+$/, "", password); if (password ~ /^v1:/) { encrypted=1 } } END { exit encrypted ? 0 : 1 }' "$TARGETS_FILE"; then
  load_f5_master_key "${CONFIG_DIR}/.MASTER_KEY"
fi

mkdir -p "$LOCAL_OUTPUT_DIR"
MAIN_CLASSES="$("${ROOT_DIR}/scripts/compile-java.sh")"
LIB_CP="${ROOT_DIR}/lib/*"

JAVA_ARGS=(fleet "$TARGETS_FILE" "$LOCAL_OUTPUT_DIR")
if [ "$DETAILS_SSH" = true ]; then
  JAVA_ARGS+=(--details-ssh)
fi

"$JAVA_CMD" -cp "$(java_classpath "$MAIN_CLASSES:$LIB_CP")" org.qypp.Main "${JAVA_ARGS[@]}"
