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

# 1. AKTIFKAN WAKELOCK (Agar HP Tidak Tidur)
echo -e "${YELLOW}[1/4] Mengaktifkan Mode Anti-Sleep...${NC}"
termux-wake-lock
echo -e "${GREEN}Wake-lock aktif! CPU tidak akan tidur.${NC}"

# 2. CEK PACKAGES
echo -e "${YELLOW}[2/4] Mengecek Java...${NC}"
if ! command -v java > /dev/null; then
    echo -e "${GREEN}Memasang Java 21...${NC}"
    pkg update && pkg upgrade -y
    pkg install tur-repo -y
    pkg install openjdk-21 -y
else
    echo -e "${GREEN}Java 21 terdeteksi.${NC}"
fi

# 3. CEK FILE SERVER
echo -e "${YELLOW}[3/4] Mengecek file server...${NC}"
if [ ! -f "paper.jar" ]; then
    echo -e "${RED}ERROR: paper.jar tidak ditemukan!${NC}"
    exit 1
fi

# 4. JALANKAN SERVER DENGAN FLAG OPTIMASI TERKUAT
echo -e "${YELLOW}[4/4] Menjalankan Server (Optimasi High-Performance)...${NC}"
echo "--------------------------------------------------------"

# RAM Oppo A3X (Disarankan 1.5GB sampai 2GB)
MEM="1536M"

java -Xms$MEM -Xmx$MEM \
    -XX:+UseG1GC \
    -XX:+ParallelRefProcEnabled \
    -XX:MaxGCPauseMillis=200 \
    -XX:+UnlockExperimentalVMOptions \
    -XX:+DisableExplicitGC \
    -XX:+AlwaysPreTouch \
    -XX:G1NewSizePercent=30 \
    -XX:G1MaxNewSizePercent=40 \
    -XX:G1HeapRegionSize=8M \
    -XX:G1ReservePercent=20 \
    -XX:G1HeapWastePercent=5 \
    -XX:G1MixedGCCountTarget=4 \
    -XX:InitiatingHeapOccupancyPercent=15 \
    -XX:G1MixedGCLiveThresholdPercent=90 \
    -XX:G1RSetUpdatingPauseTimePercent=5 \
    -XX:SurvivorRatio=32 \
    -XX:+PerfDisableSharedMem \
    -XX:MaxTenuringThreshold=1 \
    -Dusing.aikars.flags=https://mcutils.com \
    -Daikars.new.flags=true \
    -jar paper.jar nogui

# Jika server berhenti, lepaskan wakelock
termux-wake-unlock
echo -e "${YELLOW}Server berhenti. Mode Wake-lock dimatikan.${NC}"
