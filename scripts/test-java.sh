#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/scripts/java-env.sh"
MAIN_CLASSES="$("${ROOT_DIR}/scripts/compile-java.sh")"
TEST_CLASSES="${ROOT_DIR}/build/test-classes"
LIB_CP="${ROOT_DIR}/lib/*"

rm -rf "$TEST_CLASSES"
mkdir -p "$TEST_CLASSES"
shopt -s globstar nullglob

for source_file in "$ROOT_DIR"/src/test/java/**/*.java; do
  java_path "$source_file"
done > "$ROOT_DIR/build/sources-test.txt"
"$JAVAC_CMD" -cp "$(java_classpath "$MAIN_CLASSES:$LIB_CP")" -d "$(java_path "$TEST_CLASSES")" @"$(java_path "$ROOT_DIR/build/sources-test.txt")"
"$JAVA_CMD" -cp "$(java_classpath "$MAIN_CLASSES:$TEST_CLASSES:$LIB_CP")" org.qypp.f5.PlainJavaTestRunner
