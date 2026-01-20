#!/bin/bash

# Folder plugins
PLUGINS_DIR="./plugins"

# Pastikan berada di direktori server
cd "$PLUGINS_DIR" || { echo "Folder plugins tidak ditemukan!"; exit 1; }

# Loop semua file .jar
for jarfile in *.jar; do
    # Nama folder hasil ekstrak
    foldername="${jarfile%.jar}"

    # Cek apakah folder sudah ada
    if [ -d "$foldername" ]; then
        echo "Folder $foldername sudah ada, dilewati."
        continue
    fi

    # Buat folder baru
    mkdir "$foldername"

    # Ekstrak file jar ke folder
    echo "Mengekstrak $jarfile ke $foldername/"
    unzip -q "$jarfile" -d "$foldername"

    echo "Selesai mengekstrak $jarfile"
done

echo "Semua file jar sudah diproses."
