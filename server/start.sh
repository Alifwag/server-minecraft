#!/data/data/com.termux/files/usr/bin/sh

# Warna
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

clear
echo -e "${CYAN}"
echo " .S_SsS_S.    .S   .S_sSSs      sSSs    sSSs   .S_sSSs     .S_SSSs      sSSs  sdSS_SSSSSSbs "
echo ".SS~S*S~SS.  .SS  .SS~YS%%b    d%%SP   d%%SP  .SS~YS%%b   .SS~SSSSS    d%%SP  YSSS~S%SSSSSP "
echo "S%S \`Y' S%S  S%S  S%S   \`S%b  d%S'    d%S'    S%S   \`S%b  S%S   SSSS  d%S'      S%S         "
echo "S%S     S%S  S%S  S%S    S%S  S%S     S%S     S%S    S%S  S%S    S%S  S%S          S%S          "
echo "S%S     S%S  S&S  S%S    S&S  S&S     S&S     S%S    d*S  S%S SSSS%S  S&S          S&S        "
echo "S&S     S&S  S&S  S&S    S&S  S&S_Ss  S&S     S&S   .S*S  S&S  SSS%S  S&S_Ss       S&S          "
echo "S&S     S&S  S&S  S&S    S&S  S&S~SP  S&S     S&S_sdSSS   S&S    S&S  S&S~SP       S&S         "
echo "S&S     S&S  S&S  S&S    S&S  S&S     S&S     S&S~YSY%b   S&S    S&S  S&S          S&S         "
echo "S*S     S*S  S*S  S*S    S*S  S*b     S*b     S*S   \`S%b  S*S    S&S  S*b         S*S          "
echo "S*S     S*S  S*S  S*S    S*S  S*S.    S*S.    S*S    S%S  S*S    S*S  S*S          S*S          "
echo "S*S     S*S  S*S  S*S    S*S   SSSbs   SSSbs  S*S    S&S  S*S    S*S  S*S          S*S          "
echo "SSS     S*S  S*S  S*S    SSS    YSSP    YSSP  S*S    SSS  SSS    S*S  S*S          S*S           "
echo "        SP   SP   SP                          SP                 SP   SP           SP             "
echo "        Y    Y    Y                           Y                  Y    Y            Y            "
echo "  sSSs    sSSs   .S_sSSs     .S    S.     sSSs   .S_sSSs                      "
echo " d%%SP   d%%SP  .SS~YS%%b   .SS    SS.   d%%SP  .SS~YS%%b                     "
echo "d%S'    d%S'    S%S   \`S%b  S%S    S%S  d%S'    S%S   \`S%b                    "
echo "S%|     S%S     S%S    S%S  S%S    S%S  S%S     S%S    S%S                    "
echo "S&S     S&S     S%S    d*S  S&S    S%S  S&S     S%S    d*S                    "
echo "Y&Ss    S&S_Ss  S&S   .S*S  S&S    S&S  S&S_Ss  S&S   .S*S                    "
echo "\`S&&S   S&S~SP  S&S_sdSSS   S&S    S&S  S&S~SP  S&S_sdSSS                     "
echo "  \`S*S  S&S     S&S~YSY%b   S&S    S&S  S&S     S&S~YSY%b                     "
echo "   l*S  S*b     S*S   \`S%b  S*b    S*S  S*b     S*S   \`S%b                    "
echo "  .S*P  S*S.    S*S    S%S  S*S.   S*S  S*S.    S*S    S%S                    "
echo "sSS*S    SSSbs  S*S    S&S   SSSbs_S*S   SSSbs  S*S    S&S                    "
echo "YSS'      YSSP  S*S    SSS    YSSP~SSS    YSSP  S*S    SSS                    "
echo "                SP                              SP                            "
echo "                Y                               Y                             "
echo -e "${NC}"

echo -e "${GREEN}DOM Cloud - Optimized Minecraft Server${NC}"


#!/bin/bash

set -e

# ===============================
# KONFIGURASI
# ===============================
JDK_VERSION="21.0.2+13"
JDK_FOLDER="jdk-21.0.2+13"
JDK_ARCHIVE="OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.2_13.tar.gz"
JDK_URL="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2+13/${JDK_ARCHIVE}"

JAVA="$PWD/$JDK_FOLDER/bin/java"
PAPER_JAR="paper.jar"

# ===============================
# CEK JDK
# ===============================
if [ ! -d "$JDK_FOLDER" ]; then
  echo "🔍 JDK belum ditemukan"

  if [ ! -f "$JDK_ARCHIVE" ]; then
    echo "⬇️ Download JDK..."
    wget -q --show-progress "$JDK_URL"
  else
    echo "📦 File JDK archive sudah ada, skip download"
  fi

  echo "📂 Extract JDK..."
  tar -xzf "$JDK_ARCHIVE"

  echo "✅ JDK berhasil diinstall"
else
  echo "✅ JDK sudah ada, skip install"
fi

# ===============================
# CEK PAPER
# ===============================
if [ ! -f "$PAPER_JAR" ]; then
  echo "❌ paper.jar tidak ditemukan!"
  echo "➡️ Letakkan paper.jar di folder ini"
  exit 1
fi

# ===============================
# JALANKAN SERVER
# ===============================
echo "🚀 Menjalankan Minecraft Server..."
exec "$JAVA" \
  -Xms512M \
  -Xmx1200M \
  -XX:+UseG1GC \
  -XX:+ParallelRefProcEnabled \
  -XX:MaxGCPauseMillis=200 \
  -jar "$PAPER_JAR" nogui
