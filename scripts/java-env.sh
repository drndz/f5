#!/usr/bin/env bash

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

configured_jdk_home() {
  local jdk_file
  jdk_file="$(effective_config_dir)/.JDK"
  if [ -n "${F5_VALIDATION_JDK_HOME:-}" ]; then
    printf '%s\n' "$F5_VALIDATION_JDK_HOME"
    return 0
  fi
  if [ -f "$jdk_file" ]; then
    local configured
    IFS= read -r configured < "$jdk_file" || true
    configured="${configured%$'\r'}"
    if [ -n "$configured" ]; then
      printf '%s\n' "$configured"
      return 0
    fi
  fi
  if [ -n "${JAVA_HOME:-}" ]; then
    printf '%s\n' "$JAVA_HOME"
    return 0
  fi
  return 1
}

effective_config_dir() {
  local root="${ROOT_DIR:-$(pwd)}"
  local selector_file="${root}/config/.conf_effective"
  local selected="real"
  if [ -f "$selector_file" ]; then
    selected="$(sed -e 's/\r$//' "$selector_file" | awk 'NF && $1 !~ /^#/ { print; exit }')"
    selected="${selected:-real}"
  fi
  case "$selected" in
    /*|[A-Za-z]:\\*)
      printf '%s\n' "$selected"
      ;;
    *)
      printf '%s\n' "${root}/config/${selected}"
      ;;
  esac
}

resolve_java_tools() {
  local configured=""
  local jdk_home=""

  configured="$(configured_jdk_home || true)"
  if [ -n "$configured" ]; then
    jdk_home="$(normalize_jdk_home "$configured" || true)"
    if [ -z "$jdk_home" ]; then
      echo "Configured JDK path does not exist: $configured" >&2
      return 2
    fi
  fi

  if [ -n "$jdk_home" ]; then
    JAVA_CMD="${jdk_home}/bin/java"
    JAVAC_CMD="${jdk_home}/bin/javac"
  else
    JAVA_CMD="$(command -v java || true)"
    JAVAC_CMD="$(command -v javac || true)"
  fi

  if [ -z "${JAVA_CMD:-}" ] || [ -z "${JAVAC_CMD:-}" ] || [ ! -x "$JAVA_CMD" ] || [ ! -x "$JAVAC_CMD" ]; then
    echo "Could not find executable java/javac. Set F5_VALIDATION_JDK_HOME, <effective-config>/.JDK, JAVA_HOME, or PATH." >&2
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
  local key_file="${1:-$(effective_config_dir)/.MASTER_KEY}"
  if [ -n "${MASTER_KEY:-}" ]; then
    export MASTER_KEY
    return 0
  fi
  if [ ! -f "$key_file" ]; then
    echo "Master key file not found: $key_file" >&2
    echo "Create it locally as $(effective_config_dir)/.MASTER_KEY. This file is ignored by git and must not be committed." >&2
    return 1
  fi
  MASTER_KEY="$(tr -d '\r\n' < "$key_file")"
  if [ -z "$MASTER_KEY" ]; then
    echo "Master key file is empty: $key_file" >&2
    return 1
  fi
  export MASTER_KEY
}

resolve_java_tools
