if [ "$EUID" -ne 0 ]; then
    echo "[!] Tolong jalankan script ini sebagai ROOT (sudo)!"
    exit 1
fi

# =======================================================
# 1. DETEKSI OS & AUTO-INSTALL DEPENDENCIES
# =======================================================
detect_and_setup_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$ID
        OS_VERSION=$VERSION_ID
    else
        echo "[!] OS tidak terdeteksi."
        exit 1
    fi

    if [[ "$OS_NAME" == "ubuntu" || "$OS_NAME" == "debian" ]]; then
        if ! systemctl is-active --quiet iptables; then
            if systemctl is-active --quiet ufw; then
                ufw disable > /dev/null 2>&1
                systemctl disable ufw > /dev/null 2>&1
            fi
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y > /dev/null 2>&1
            apt-get install iptables-persistent netfilter-persistent -y > /dev/null 2>&1
            systemctl enable netfilter-persistent > /dev/null 2>&1
            systemctl start netfilter-persistent > /dev/null 2>&1
        fi
        SAVE_COMMAND="netfilter-persistent save"

    elif [[ "$OS_NAME" == "almalinux" || "$OS_NAME" == "rocky" || "$OS_NAME" == "rhel" || "$OS_NAME" == "centos" ]]; then
        if ! systemctl is-active --quiet iptables; then
            if systemctl is-active --quiet firewalld; then
                systemctl stop firewalld > /dev/null 2>&1
                systemctl disable firewalld > /dev/null 2>&1
            fi
            dnf install iptables-services -y > /dev/null 2>&1
            systemctl enable iptables > /dev/null 2>&1
            systemctl start iptables > /dev/null 2>&1
        fi
        SAVE_COMMAND="service iptables save"
    fi
}

detect_and_setup_os

# =======================================================
# 2. MANAJEMEN KONFIGURASI PERSISTEN
# =======================================================
CONFIG_FILE="/etc/manage-fw.conf"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    PUBLIC_PORTS="1745 443 853 8080"
    RESTRICTED_RULES=""
fi

save_config() {
    echo "PUBLIC_PORTS=\"$PUBLIC_PORTS\"" > "$CONFIG_FILE"
    echo "RESTRICTED_RULES=\"$RESTRICTED_RULES\"" >> "$CONFIG_FILE"
}

# =======================================================
# 3. ENGINE IPTABLES CORE
# =======================================================
apply_rules() {
    echo -e "\n[+] Membersihkan rule lama & menerapkan konfigurasi baru..."
    iptables -F
    iptables -X
    iptables -Z
    
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    
    echo "[+] Menerapkan Granular Whitelist Port..."
    local restricted_ports=$(echo "$RESTRICTED_RULES" | tr ' ' '\n' | cut -d':' -f1 | sort -u | tr '\n' ' ')
    
    for rule in $RESTRICTED_RULES; do
        local port=$(echo "$rule" | cut -d':' -f1)
        local ip=$(echo "$rule" | cut -d':' -f2)
        if [ ! -z "$port" ] && [ ! -z "$ip" ]; then
            iptables -A INPUT -p tcp -s "$ip" --dport "$port" -j ACCEPT
            iptables -A INPUT -p udp -s "$ip" --dport "$port" -j ACCEPT
            echo "    -> [ALLOWED] IP $ip boleh akses Port $port (TCP/UDP)"
        fi
    done
    
    for r_port in $restricted_ports; do
        if [ ! -z "$r_port" ]; then
            iptables -A INPUT -p tcp --dport "$r_port" -j DROP
            iptables -A INPUT -p udp --dport "$r_port" -j DROP
            echo "    -> [GATED] Port $r_port dikunci rapat dari publik!"
        fi
    done
    
    echo "[+] Membuka Public Ports..."
    for port in $PUBLIC_PORTS; do
        if [ ! -z "$port" ]; then
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT
            echo "    -> [OPEN PUBLIC] Port $port terbuka untuk semua IP"
        fi
    done
    
    if [ ! -z "$RESTRICTED_RULES" ]; then
        iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
        iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited
    fi
    
    echo "[+] Menyimpan aturan ke sistem agar persisten..."
    eval $SAVE_COMMAND > /dev/null 2>&1
    echo "[+] Sukses! Semua aturan berhasil dipasang secara aktif and persisten."
}

show_status() {
    clear
    echo "========================================================="
    echo "        DYNAMIC GRANULAR FIREWALL MANAGER v3.6           "
    echo "========================================================="
    echo "  [PORT BUKA UNTUK PUBLIK (Both TCP/UDP)]"
    echo "  -> $PUBLIC_PORTS"
    echo "---------------------------------------------------------"
    echo "  [PORT GRANULAR (Hanya IP tertentu yang bisa akses)]"
    if [ -z "$RESTRICTED_RULES" ] || [ "$RESTRICTED_RULES" == " " ]; then
        echo "  -> (Kosong)"
    else
        for rule in $RESTRICTED_RULES; do
            local p=$(echo "$rule" | cut -d':' -f1)
            local i=$(echo "$rule" | cut -d':' -f2)
            if [ ! -z "$p" ] && [ ! -z "$i" ]; then
                echo "  -> Port $p hanya untuk IP: $i"
            fi
        done
    fi
    echo "========================================================="
}

# =======================================================
# 4. INTERACTIVE MENU LOOP
# =======================================================
while true; do
    show_status
    echo "PILIH MENU:"
    echo "1) AUTO-DETECT ALL LISTENING PORTS & OPEN (Rekomendasi Awal)"
    echo "2) TAMBAH Port Terbuka untuk UMUM (Bisa pisah koma/spasi)"
    echo "3) HAPUS Port Terbuka untuk UMUM"
    echo "4) TAMBAH Rule Granular (Kunci Port ke IP tertentu)"
    echo "5) HAPUS Rule Granular"
    echo "6) BUKA TOTAL FIREWALL (Flush & Open All Ports)"
    echo "7) TERAPKAN & SIMPAN FIREWALL (Apply & Save)"
    echo "8) Lihat Urutan iptables Aktif Berjalan"
    echo "9) Keluar"
    read -p "Masukkan pilihan [1-9]: " opsi

    case $opsi in
        1)
            echo -e "\n[+] Mencari port yang sedang berstatus LISTEN di sistem..."
            
            # Strategi Baru v3.6: Hancurkan semua spasi berlebih, cari semua teks sebelum users:(
            # Tangkap pola titik dua + angka (:PORT) baik format IPv4, IPv6, maupun bintang (*)
            if command -v ss &> /dev/null; then
                detected_list=$(ss -tulpn | tr -s ' ' | grep -vi "peer" | sed -E 's/users:\(\(.*//g' | grep -oE ':[0-9]+ ' | tr -d ': ' | sort -n -u | tr '\n' ' ')
            else
                detected_list=$(netstat -tulpn | tr -s ' ' | grep -i "listen" | awk '{print $4}' | awk -F':' '{print $NF}' | sort -n -u | tr '\n' ' ')
            fi

            # Keamanan: Buang port 0 atau spasi kosong liar jika ada
            detected_list=$(echo "$detected_list" | sed -E 's/\b(0)\b//g' | tr -s ' ')

            if [ -z "$detected_list" ] || [ "$detected_list" == " " ] || [ "$detected_list" == "" ]; then
                echo "[!] Tidak mendeteksi ada port yang sedang listen aktif saat ini."
                sleep 2
            else
                comma_view=$(echo "$detected_list" | tr ' ' ',' | sed 's/,$//' | sed 's/^,//')
                echo -e "-> Menemukan port aktif: \033[1;32m$comma_view\033[0m"
                
                read -p "Apakah kamu yakin ingin memasukkan SEMUA port tersebut ke daftar PUBLIC OPEN? (y/n): " konfirmasi
                if [[ "$konfirmasi" == "y" || "$konfirmasi" == "Y" ]]; then
                    if [[ "$PUBLIC_PORTS" == *"Semua Port"* ]]; then
                        PUBLIC_PORTS=""
                    fi
                    
                    for p_detect in $detected_list; do
                        if [[ ! " $PUBLIC_PORTS " =~ " $p_detect " ]]; then
                            PUBLIC_PORTS="$PUBLIC_PORTS $p_detect"
                        fi
                    done
                    
                    PUBLIC_PORTS=$(echo $PUBLIC_PORTS | tr -s ' ' | sed -e 's/^[ \t]*//;s/[ \t]*$//')
                    save_config
                    echo "[+] Sukses mengimpor daftar port otomatis. Silakan jalankan Menu 7 (Apply) untuk mengaktifkan."
                    sleep 2.5
                else
                    echo "[!] Dibatalkan."; sleep 1
                fi
            fi
            ;;
        2)
            read -p "Masukkan port baru (contoh: 80,443,3000 atau 80 443 3000): " input_ports
            cleaned_ports=$(echo "$input_ports" | tr ',' ' ' | tr -s ' ')
            if [[ "$PUBLIC_PORTS" == *"Semua Port"* ]]; then PUBLIC_PORTS=""; fi

            any_valid=false
            for port in $cleaned_ports; do
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                    if [[ ! " $PUBLIC_PORTS " =~ " $port " ]]; then
                        PUBLIC_PORTS="$PUBLIC_PORTS $port"
                    fi
                    any_valid=true
                else
                    echo "[!] Port '$port' tidak valid (bukan angka), dilewati."
                fi
            done
            PUBLIC_PORTS=$(echo $PUBLIC_PORTS | tr -s ' ' | sed -e 's/^[ \t]*//;s/[ \t]*$//')
            save_config
            if [ "$any_valid" = true ]; then
                echo "[+] Port berhasil ditambahkan ke list temporary."; sleep 1
            else
                echo "[!] Tidak ada port valid yang ditambahkan."; sleep 1.5
            fi
            ;;
        3)
            read -p "Masukkan port umum yang mau dihapus (bisa pisah koma/spasi): " del_ports
            cleaned_del=$(echo "$del_ports" | tr ',' ' ' | tr -s ' ')
            for port in $cleaned_del; do
                PUBLIC_PORTS=$(echo $PUBLIC_PORTS | sed -e "s/\b$port\b//g")
            done
            PUBLIC_PORTS=$(echo $PUBLIC_PORTS | tr -s ' ' | sed -e 's/^[ \t]*//;s/[ \t]*$//')
            save_config
            ;;
        4)
            read -p "Masukkan nomor port yang mau dikunci (misal: 53, 3306): " g_port
            read -p "Masukkan IP/Subnet yang diizinkan (misal: 1.1.1.1 atau 10.0.0.0/24): " g_ip
            if [ ! -z "$g_port" ] && [ ! -z "$g_ip" ]; then
                new_rule="$g_port:$g_ip"
                [[ ! " $RESTRICTED_RULES " =~ " $new_rule " ]] && RESTRICTED_RULES="$RESTRICTED_RULES $new_rule"
                save_config
            fi
            ;;
        5)
            echo "Ketik persis format 'PORT:IP' yang ingin dihapus dari list status di atas."
            read -p "Masukkan target rule (contoh 53:202.10.44.110): " del_rule
            local escaped_del_rule=$(echo "$del_rule" | sed 's|/|\\/|g')
            RESTRICTED_RULES=$(echo $RESTRICTED_RULES | sed -e "s|\b$escaped_del_rule\b||g" -e 's/^[ \t]*//;s/[ \t]*$//')
            save_config
            ;;
        6)
            read -p "Apakah kamu yakin ingin MENGHAPUS ALL RULES dan MEMBUKA SEMUA PORT? (y/n): " konfirmasi
            if [[ "$konfirmasi" == "y" || "$konfirmasi" == "Y" ]]; then
                iptables -F
                iptables -X
                iptables -Z
                iptables -P INPUT ACCEPT
                iptables -P FORWARD ACCEPT
                iptables -P OUTPUT ACCEPT
                eval $SAVE_COMMAND > /dev/null 2>&1
                
                PUBLIC_PORTS="Semua Port Terbuka (Firewall OFF)"
                RESTRICTED_RULES=""
                save_config
                echo "[+] FIREWALL DI-FLUSH TOTAL! Semua port sekarang TERBUKA LEBAR (ACCEPT ALL)."
                sleep 2
            fi
            ;;
        7)
            if [[ "$PUBLIC_PORTS" == *"Semua Port"* ]]; then
                PUBLIC_PORTS="1745 443 853 8080"
            fi
            apply_rules
            read -p "Tekan [Enter] untuk kembali..."
            ;;
        8)
            clear
            echo "=== CURRENT ACTIVE IPTABLES RULES ==="
            iptables -L -n -v --line-numbers
            echo "====================================="
            read -p "Tekan [Enter] untuk kembali..."
            ;;
        9)
            echo "Keluar."
            exit 0
            ;;
        *)
            echo "Pilihan tidak valid!"
            sleep 1
            ;;
    esac
done
