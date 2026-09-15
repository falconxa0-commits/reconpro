#!/usr/bin/env bash
# Compile the SDK + tests + example, run tests, run the example offline.
# Exits nonzero on any failure.
#
# Compiler: prefers `javac`. This sandbox ships a JRE-only OpenJDK 21 (java present,
# javac ABSENT), so we fall back to the Eclipse batch compiler (ecj) run via
# `java -jar` — downloaded once from Maven Central if missing. Override with ECJ_JAR.
set -euo pipefail
cd "$(dirname "$0")"

if command -v javac >/dev/null 2>&1; then
  JAVAC=(javac)
else
  ECJ_JAR="${ECJ_JAR:-/tmp/tools/ecj.jar}"
  if [ ! -f "$ECJ_JAR" ]; then
    mkdir -p "$(dirname "$ECJ_JAR")"
    curl -sSL -o "$ECJ_JAR" \
      https://repo1.maven.org/maven2/org/eclipse/jdt/ecj/3.36.0/ecj-3.36.0.jar
  fi
  JAVAC=(java -jar "$ECJ_JAR" -source 21 -target 21)
fi

rm -rf build
mkdir -p build

"${JAVAC[@]}" -d build src/main/java/com/reconpro/sdk/ReconProClient.java
"${JAVAC[@]}" -cp build -d build src/test/java/ClientTest.java
"${JAVAC[@]}" -cp build -d build examples/Basic.java

java -cp build ClientTest
java -cp build Basic --offline
echo "BUILD+TESTS OK"
