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

# 1. CEK STORAGE
echo -e "${YELLOW}[1/4] Mengecek storage...${NC}"
df -h | grep -E "/dev/root|/dev/sda1|/dev/vda1" || df -h .

# 2. CEK JAVA
echo -e "${YELLOW}[2/4] Mengecek Java...${NC}"
if ! command -v java > /dev/null; then
    echo -e "${GREEN}Memasang Java...${NC}"
    
    # Cek OS
    if [ -f /etc/os-release ]; then
        OS=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')
        
        case $OS in
            "ubuntu"|"debian")
                echo -e "${GREEN}OS: $OS - Install OpenJDK 17${NC}"
                apt update && apt upgrade -y
                apt install openjdk-17-jdk-headless -y
                ;;
            "alpine")
                echo -e "${GREEN}OS: Alpine - Install OpenJDK 17${NC}"
                apk update && apk upgrade
                apk add openjdk17
                ;;
            *)
                echo -e "${GREEN}OS: Unknown - Trying default package manager${NC}"
                if command -v apt > /dev/null; then
                    apt update && apt install openjdk-17-jdk-headless -y
                elif command -v yum > /dev/null; then
                    yum install java-17-openjdk -y
                elif command -v apk > /dev/null; then
                    apk add openjdk17
                else
                    echo -e "${RED}Package manager not found!${NC}"
                    exit 1
                fi
                ;;
        esac
    else
        echo -e "${RED}Cannot detect OS!${NC}"
        exit 1
    fi
else
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
    echo -e "${GREEN}Java terdeteksi: $JAVA_VERSION${NC}"
fi

# 3. CEK FILE SERVER
echo -e "${YELLOW}[3/4] Mengecek file server...${NC}"
if [ ! -f "paper.jar" ]; then
    echo -e "${RED}ERROR: paper.jar tidak ditemukan!${NC}"
    
    # Cek apakah ada file JAR lain
    JAR_FILES=$(ls *.jar 2>/dev/null | head -1)
    if [ -n "$JAR_FILES" ]; then
        echo -e "${GREEN}File JAR ditemukan: $JAR_FILES${NC}"
        echo -e "${GREEN}Menggunakan $JAR_FILES sebagai server${NC}"
        SERVER_JAR="$JAR_FILES"
    else
        echo -e "${RED}Tidak ada file JAR ditemukan!${NC}"
        echo -e "${YELLOW}Download PaperMC? (y/n): ${NC}"
        read DOWNLOAD_CHOICE
        
        if [ "$DOWNLOAD_CHOICE" = "y" ] || [ "$DOWNLOAD_CHOICE" = "Y" ]; then
            echo -e "${GREEN}Mendownload PaperMC 1.20.4...${NC}"
            wget https://api.papermc.io/v2/projects/paper/versions/1.20.4/builds/494/downloads/paper-1.20.4-494.jar -O paper.jar
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}Download berhasil!${NC}"
                SERVER_JAR="paper.jar"
            else
                echo -e "${RED}Download gagal!${NC}"
                exit 1
            fi
        else
            exit 1
        fi
    fi
else
    SERVER_JAR="paper.jar"
    echo -e "${GREEN}paper.jar ditemukan!${NC}"
fi

# 4. PRE-START OPTIMIZATION FOR DOM CLOUD
echo -e "${YELLOW}[4/4] Optimasi untuk DOM Cloud...${NC}"

# Clean up temporary files
rm -rf /tmp/* 2>/dev/null

# Create essential server files if they don't exist
if [ ! -f "server.properties" ]; then
    echo -e "${GREEN}Membuat server.properties default...${NC}"
    cat > server.properties << EOF
#Minecraft server properties
max-players=10
view-distance=6
simulation-distance=4
online-mode=false
white-list=false
difficulty=easy
gamemode=survival
level-type=default
motd=DOM Cloud Server
network-compression-threshold=256
sync-chunk-writes=true
enable-command-block=false
max-world-size=10000
EOF
fi

if [ ! -f "eula.txt" ]; then
    echo -e "${GREEN}Membuat eula.txt...${NC}"
    echo "eula=true" > eula.txt
fi

# Create optimized startup script
cat > optimized_flags.txt << EOF
Optimasi untuk DOM Cloud:
- RAM: 1.2GB (sesuai spesifikasi)
- View Distance: 6 (reduced)
- Simulation Distance: 4 (reduced)
- Network Compression: aktif
- G1GC dengan pengaturan hemat memori
EOF

cat optimized_flags.txt

echo "--------------------------------------------------------"

# 5. JALANKAN SERVER DENGAN OPTIMASI DOM CLOUD
echo -e "${YELLOW}[5/5] Menjalankan Server (Optimasi DOM Cloud)...${NC}"

# RAM allocation for DOM Cloud (adjust based on available memory)
# Total RAM ~1.5GB, allocate 1.2GB for server
MEM="1200M"

echo -e "${GREEN}Menggunakan RAM: $MEM${NC}"
echo -e "${GREEN}Server akan dimulai dalam 3 detik...${NC}"
sleep 3

java -Xms$MEM -Xmx$MEM \
    -XX:+UseG1GC \
    -XX:+ParallelRefProcEnabled \
    -XX:MaxGCPauseMillis=150 \
    -XX:+UnlockExperimentalVMOptions \
    -XX:+DisableExplicitGC \
    -XX:+AlwaysPreTouch \
    -XX:G1NewSizePercent=20 \
    -XX:G1MaxNewSizePercent=35 \
    -XX:G1HeapRegionSize=4M \
    -XX:G1ReservePercent=15 \
    -XX:G1HeapWastePercent=5 \
    -XX:G1MixedGCCountTarget=8 \
    -XX:InitiatingHeapOccupancyPercent=10 \
    -XX:G1MixedGCLiveThresholdPercent=95 \
    -XX:G1RSetUpdatingPauseTimePercent=3 \
    -XX:SurvivorRatio=32 \
    -XX:+PerfDisableSharedMem \
    -XX:MaxTenuringThreshold=1 \
    -XX:+UseStringDeduplication \
    -XX:+OptimizeStringConcat \
    -XX:+UseFastAccessorMethods \
    -Dcom.mojang.eula.agree=true \
    -DIReallyKnowWhatIAmDoingISwear=true \
    -Dfile.encoding=UTF-8 \
    -jar "$SERVER_JAR" nogui

# Jika server crash/stop
echo -e "${RED}Server berhenti!${NC}"
echo -e "${YELLOW}Restart dalam 10 detik...${NC}"
sleep 10
exec $0
