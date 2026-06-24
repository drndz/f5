#!/usr/bin/env bash

DEFAULT_F5_VALIDATION_JDK_HOME='C:\Users\sergq\.jdks\ms-17.0.19'

normalize_jdk_home() {
  local candidate="$1"
  if [ -z "$candidate" ]; then
    return 1
  fi

  if [ -d "$candidate" ]; then
    printf '%s\n' "$candidate"
    return 0
  fi

  if command -v cygpath >/dev/null 2>&1; then
    local converted
    converted="$(cygpath -u "$candidate" 2>/dev/null || true)"
    if [ -n "$converted" ] && [ -d "$converted" ]; then
      printf '%s\n' "$converted"
      return 0
    fi
  fi

  case "$candidate" in
    [A-Za-z]:\\*)
      local drive rest converted
      drive="$(printf '%s' "${candidate:0:1}" | tr '[:upper:]' '[:lower:]')"
      rest="${candidate:2}"
      rest="${rest//\\//}"
      for converted in "/${drive}${rest}" "/mnt/${drive}${rest}"; do
        if [ -d "$converted" ]; then
          printf '%s\n' "$converted"
          return 0
        fi
      done
      ;;
  esac

  return 1
}

resolve_java_tools() {
  local configured="${F5_VALIDATION_JDK_HOME:-${JAVA_HOME:-}}"
  local jdk_home=""

  if [ -n "$configured" ]; then
    jdk_home="$(normalize_jdk_home "$configured" || true)"
    if [ -z "$jdk_home" ]; then
      echo "Configured JDK path does not exist: $configured" >&2
      return 2
    fi
  else
    jdk_home="$(normalize_jdk_home "$DEFAULT_F5_VALIDATION_JDK_HOME" || true)"
  fi

  if [ -n "$jdk_home" ]; then
    JAVA_CMD="${jdk_home}/bin/java"
    JAVAC_CMD="${jdk_home}/bin/javac"
  else
    JAVA_CMD="$(command -v java || true)"
    JAVAC_CMD="$(command -v javac || true)"
  fi

  if [ -z "${JAVA_CMD:-}" ] || [ -z "${JAVAC_CMD:-}" ] || [ ! -x "$JAVA_CMD" ] || [ ! -x "$JAVAC_CMD" ]; then
    echo "Could not find executable java/javac. Set F5_VALIDATION_JDK_HOME or JAVA_HOME." >&2
    return 2
  fi

  export JAVA_CMD JAVAC_CMD
}

java_path() {
  if command -v cygpath >/dev/null 2>&1 && [[ "${JAVA_CMD:-}" != /usr/bin/* && "${JAVA_CMD:-}" != /bin/* ]]; then
    cygpath -w "$1"
  else
    printf '%s\n' "$1"
  fi
}

java_classpath() {
  local value="$1"
  if command -v cygpath >/dev/null 2>&1 && [[ "${JAVA_CMD:-}" != /usr/bin/* && "${JAVA_CMD:-}" != /bin/* ]]; then
    cygpath -wp "$value"
  else
    printf '%s\n' "$value"
  fi
}

load_f5_master_key() {
  local key_file="${1:-${ROOT_DIR:-$(pwd)}/config/.F5_MASTER_KEY}"
  if [ -n "${F5_MASTER_KEY:-}" ]; then
    export F5_MASTER_KEY
    return 0
  fi
  if [ ! -f "$key_file" ]; then
    echo "Master key file not found: $key_file" >&2
    echo "Create it locally as config/.F5_MASTER_KEY. This file is ignored by git and must not be committed." >&2
    return 1
  fi
  F5_MASTER_KEY="$(tr -d '\r\n' < "$key_file")"
  if [ -z "$F5_MASTER_KEY" ]; then
    echo "Master key file is empty: $key_file" >&2
    return 1
  fi
  export F5_MASTER_KEY
}

resolve_java_tools
