#!/usr/bin/env bash
# Builds auditor.jar using only the JDK (Java 17+). No Maven needed.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf build && mkdir -p build/classes
javac --release 17 -Xlint:all -d build/classes $(find src/main/java -name '*.java')
jar --create --file auditor.jar --main-class auditor.Main -C build/classes .
rm -rf build
echo "Built auditor.jar  ->  sudo java -jar auditor.jar"
