#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build/classes"
LIB_CP="${ROOT_DIR}/lib/*"

source "${ROOT_DIR}/scripts/java-env.sh"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
shopt -s globstar nullglob

for source_file in "$ROOT_DIR"/src/main/java/**/*.java; do
  java_path "$source_file"
done > "$ROOT_DIR/build/sources-main.txt"
"$JAVAC_CMD" -cp "$(java_classpath "$LIB_CP")" -d "$(java_path "$BUILD_DIR")" @"$(java_path "$ROOT_DIR/build/sources-main.txt")"

echo "$BUILD_DIR"
