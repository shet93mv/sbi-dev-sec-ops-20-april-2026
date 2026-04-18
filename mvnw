#!/bin/sh
# Maven Wrapper — downloads Maven 3.9.6 if not present
MAVEN_HOME="${HOME}/.mvn/wrapper/maven"
MAVEN_BIN="${MAVEN_HOME}/bin/mvn"
MAVEN_URL="https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip"

if [ ! -f "${MAVEN_BIN}" ]; then
  echo "Downloading Maven 3.9.6..."
  mkdir -p "${MAVEN_HOME}"
  curl -sL "${MAVEN_URL}" -o /tmp/maven.zip
  unzip -q /tmp/maven.zip -d "${HOME}/.mvn/wrapper/"
  mv "${HOME}/.mvn/wrapper/apache-maven-3.9.6/"* "${MAVEN_HOME}/"
  chmod +x "${MAVEN_BIN}"
fi

exec "${MAVEN_BIN}" "$@"
