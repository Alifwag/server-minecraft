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
JAVA="$PWD/jdk-21.0.2+13/bin/java"

$JAVA -Xms512M -Xmx1200M -XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200 -jar paper.jar nogui
