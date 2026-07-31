#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run this script as ROOT (sudo)!"
    exit 1
fi

CONFIG_FILE="/etc/manage-fw.conf"
NFT_CONF="/etc/nftables.conf"

# =======================================================
# 1. OS DETECTION & PREPARE ENVIRONMENT
# =======================================================
detect_and_setup_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$ID
    else
        echo "[!] OS not detected."
        exit 1
    fi

    # Matikan service firewall lain & fail2ban yang berpotensi bentrok
    local services_to_stop=("ufw" "firewalld" "iptables" "fail2ban")
    for srv in "${services_to_stop[@]}"; do
        if systemctl is-active --quiet "$srv" 2>/dev/null || systemctl is-enabled --quiet "$srv" 2>/dev/null; then
            echo "[+] Disabling conflicting service: $srv..."
            systemctl stop "$srv" > /dev/null 2>&1
            systemctl disable "$srv" > /dev/null 2>&1
        fi
    done

    # Pastikan nftables terinstall
    if ! command -v nft &> /dev/null; then
        echo "[+] Installing nftables..."
        if [[ "$OS_NAME" == "ubuntu" || "$OS_NAME" == "debian" ]]; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y > /dev/null 2>&1
            apt-get install nftables -y > /dev/null 2>&1
        elif [[ "$OS_NAME" == "almalinux" || "$OS_NAME" == "rocky" || "$OS_NAME" == "rhel" || "$OS_NAME" == "centos" ]]; then
            dnf install nftables -y > /dev/null 2>&1
        fi
    fi

    systemctl enable nftables > /dev/null 2>&1
    systemctl start nftables > /dev/null 2>&1
}

detect_and_setup_os

# =======================================================
# 2. PERSISTENT CONFIGURATION MANAGEMENT
# =======================================================
clean_ports_string() {
    local raw_input="$1"
    echo "$raw_input" | tr ',' ' ' | tr '\n' ' ' | tr -s ' ' | xargs -n1 2>/dev/null | grep -E '^[0-9]+$' | awk '$1>=1 && $1<=65535' | sort -n -u | tr '\n' ' ' | sed -e 's/^[ \t]*//;s/[ \t]*$//'
}

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    PUBLIC_PORTS=""
    RESTRICTED_RULES=""
fi

save_config() {
    PUBLIC_PORTS=$(clean_ports_string "$PUBLIC_PORTS")
    RESTRICTED_RULES=$(echo "$RESTRICTED_RULES" | tr -s ' ' | sed -e 's/^[ \t]*//;s/[ \t]*$//')
    echo "PUBLIC_PORTS=\"$PUBLIC_PORTS\"" > "$CONFIG_FILE"
    echo "RESTRICTED_RULES=\"$RESTRICTED_RULES\"" >> "$CONFIG_FILE"
}

# =======================================================
# 3. NFTABLES CORE ENGINE
# =======================================================
apply_rules() {
    echo -e "\n[+] Generating native nftables ruleset..."

    PUBLIC_PORTS=$(clean_ports_string "$PUBLIC_PORTS")
    local check_rules=$(echo "$RESTRICTED_RULES" | tr -d ' ')

    # ---------------------------------------------------
    # FAIL-SAFE CHECK: Jika daftar port publik dan rule kosong
    # ---------------------------------------------------
    if [ -z "$PUBLIC_PORTS" ] && [ -z "$check_rules" ]; then
        echo -e "\033[1;33m[!] WARNING: No public ports or restricted rules configured!\033[0m"
        echo -e "\033[1;32m[+] Activating FAIL-SAFE mode: Opening ALL ports to prevent system lockout.\033[0m"
        
        cat << 'EOF' > "$NFT_CONF"
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy accept;
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF
        nft -f "$NFT_CONF"
        echo "[+] Fail-safe policy deployed successfully."
        return
    fi

    # ---------------------------------------------------
    # GENERATE FILTER RULES (Jika ada port yang dikonfigurasi)
    # ---------------------------------------------------
    cat << 'EOF' > "$NFT_CONF"
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy accept;

        # Allow Loopback & Connection Tracking
        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop

        # Allow ICMP (Ping v4 & v6)
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept

        # Allow WireGuard / Tunnel interfaces
        iifname { "wg*", "tun*", "ppp*" } accept

EOF

    # A. Whitelist IP Rules
    if [ ! -z "$check_rules" ]; then
        echo "        # --- Granular Whitelist Rules ---" >> "$NFT_CONF"
        for rule in $RESTRICTED_RULES; do
            local port=$(echo "$rule" | cut -d':' -f1)
            local ip=$(echo "$rule" | cut -d':' -f2)
            if [ ! -z "$port" ] && [ ! -z "$ip" ]; then
                if [[ "$ip" =~ : ]]; then
                    echo "        ip6 saddr $ip meta l4proto { tcp, udp } th dport $port accept" >> "$NFT_CONF"
                else
                    echo "        ip saddr $ip meta l4proto { tcp, udp } th dport $port accept" >> "$NFT_CONF"
                fi
                echo "    -> [ACCEPT] Source: $ip -> Destination Port: $port"
            fi
        done

        local restricted_ports=$(echo "$RESTRICTED_RULES" | tr ' ' '\n' | cut -d':' -f1 | sort -u | tr '\n' ' ')
        echo "        # --- Block Restricted Ports Globally ---" >> "$NFT_CONF"
        for r_port in $restricted_ports; do
            if [ ! -z "$r_port" ]; then
                echo "        meta l4proto { tcp, udp } th dport $r_port drop" >> "$NFT_CONF"
                echo "    -> [DROP] Destination Port: $r_port (Public Access Blocked)"
            fi
        done
    fi

    # B. Open Public Ports
    if [ ! -z "$PUBLIC_PORTS" ]; then
        local formatted_public_ports=$(echo "$PUBLIC_PORTS" | tr ' ' ',')
        echo "        # --- Open Public Ports (TCP & UDP) ---" >> "$NFT_CONF"
        if [[ "$formatted_public_ports" =~ "," ]]; then
            echo "        meta l4proto { tcp, udp } th dport { $formatted_public_ports } accept" >> "$NFT_CONF"
        else
            echo "        meta l4proto { tcp, udp } th dport $formatted_public_ports accept" >> "$NFT_CONF"
        fi
        echo "    -> [ACCEPT] Public Ports Open: $formatted_public_ports"
    fi

    # C. Default Catch-All Block & Forward Rules
    cat << 'EOF' >> "$NFT_CONF"

        # --- Default Catch-All Drop ---
        reject with icmpx type admin-prohibited
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
        ct state established,related accept
        iifname { "wg*", "tun*", "ppp*" } accept
        oifname { "wg*", "tun*", "ppp*" } accept
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF

    echo "[+] Loading ruleset into Linux Kernel..."
    nft -f "$NFT_CONF"
    
    if [ $? -eq 0 ]; then
        echo "[+] Success: nftables rules deployed and saved to $NFT_CONF"
    else
        echo "[!] ERROR: Failed to apply nftables ruleset!"
    fi
}

show_status() {
    clear
    echo "========================================================="
    echo "        DYNAMIC GRANULAR FIREWALL MANAGER (NFTABLES v4.3) "
    echo "========================================================="
    echo "  [PUBLIC OPEN PORTS (TCP/UDP)]"
    if [ -z "$PUBLIC_PORTS" ]; then
        echo "  -> (None - System in Open-All / Unrestricted mode)"
    else
        echo "  -> $PUBLIC_PORTS"
    fi
    echo "---------------------------------------------------------"
    echo "  [GRANULAR RESTRICTED RULES (Port access restricted by IP)]"
    local check_rules=$(echo "$RESTRICTED_RULES" | tr -d ' ')
    if [ -z "$check_rules" ]; then
        echo "  -> (None)"
    else
        for rule in $RESTRICTED_RULES; do
            local p=$(echo "$rule" | cut -d':' -f1)
            local i=$(echo "$rule" | cut -d':' -f2)
            if [ ! -z "$p" ] && [ ! -z "$i" ]; then
                echo "  -> Port $p restricted to IP/Subnet: $i"
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
    echo "SELECT AN OPTION:"
    echo "1) Auto-detect all listening ports and add to public list"
    echo "2) Add public open ports (comma or space separated)"
    echo "3) Remove public open ports"
    echo "4) Add port rule (restrict port to specific IP/Subnet)"
    echo "5) Remove port rule"
    echo "6) RESET / FLUSH ALL (Open ALL ports and clear config)"
    echo "7) Apply and save active rules"
    echo "8) View live running nftables ruleset"
    echo "9) Exit"
    read -p "Enter selection [1-9]: " opsi

    case $opsi in
        1)
            echo -e "\n[+] Scanning system for active listening ports..."
            
            if command -v ss &> /dev/null; then
                detected_list=$(ss -tulpnH | awk '{print $5}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^[0-9]+$' | awk '$1>=1 && $1<=65535' | sort -n -u | tr '\n' ' ')
            else
                detected_list=$(netstat -tulpn 2>/dev/null | grep LISTEN | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^[0-9]+$' | awk '$1>=1 && $1<=65535' | sort -n -u | tr '\n' ' ')
            fi

            if [ -z "$detected_list" ] || [ "$detected_list" == " " ]; then
                echo "[!] No active listening ports detected."
                sleep 2
            else
                comma_view=$(echo "$detected_list" | clean_ports_string "$detected_list" | tr ' ' ',')
                echo -e "-> Detected active ports: \033[1;32m$comma_view\033[0m"
                
                read -p "Add ALL detected ports to the public list? (y/n): " konfirmasi
                if [[ "$konfirmasi" == "y" || "$konfirmasi" == "Y" ]]; then
                    PUBLIC_PORTS="$PUBLIC_PORTS $detected_list"
                    save_config
                    echo "[+] Ports imported to list. Run Option 7 to apply changes."
                    sleep 2
                else
                    echo "[!] Operation cancelled."; sleep 1
                fi
            fi
            ;;
        2)
            read -p "Enter public ports to add (e.g., 80,443,3000 or 80 443 3000): " input_ports
            cleaned_ports=$(clean_ports_string "$input_ports")
            
            if [ ! -z "$cleaned_ports" ]; then
                PUBLIC_PORTS="$PUBLIC_PORTS $cleaned_ports"
                save_config
                echo "[+] Ports added to temporary list. Run Option 7 to apply changes."; sleep 2
            else
                echo "[!] No valid ports entered (must be 1-65535)."; sleep 2
            fi
            ;;
        3)
            read -p "Enter public ports to remove (comma or space separated): " del_ports
            cleaned_del=$(clean_ports_string "$del_ports")
            for port in $cleaned_del; do
                PUBLIC_PORTS=$(echo " $PUBLIC_PORTS " | sed -e "s| $port | |g")
            done
            save_config
            echo "[+] Ports removed from list. Run Option 7 to apply changes."
            sleep 2
            ;;
        4)
            read -p "Enter port number to restrict (1-65535): " g_port
            read -p "Enter allowed IP/Subnet (e.g., 1.1.1.1 or 10.0.0.0/24): " g_ip
            if [ ! -z "$g_port" ] && [ ! -z "$g_ip" ]; then
                g_port=$(echo "$g_port" | tr -d ' ')
                g_ip=$(echo "$g_ip" | tr -d ' ')
                
                if [[ "$g_port" =~ ^[0-9]+$ ]] && [ "$g_port" -ge 1 ] && [ "$g_port" -le 65535 ]; then
                    new_rule="$g_port:$g_ip"
                    if [[ ! " $RESTRICTED_RULES " =~ " $new_rule " ]]; then
                        RESTRICTED_RULES="$RESTRICTED_RULES $new_rule"
                    fi
                    save_config
                    echo "[+] Rule added. Run Option 7 to apply changes."
                    sleep 2
                else
                    echo "[!] Invalid port number!"; sleep 2
                fi
            fi
            ;;
        5)
            echo "Enter the exact 'PORT:IP' format to remove as listed in status."
            read -p "Enter target rule (e.g., 53:1.1.1.1): " del_rule
            
            if [ ! -z "$del_rule" ]; then
                del_rule=$(echo "$del_rule" | tr -d ' ')
                RESTRICTED_RULES=$(echo " $RESTRICTED_RULES " | sed -E "s| $del_rule[^ ]* ||g" -e 's/  */ /g')
                save_config
                echo -e "\033[1;32m[+] Rule cleared from config.\033[0m"
            else
                echo "[!] No input provided."
            fi
            
            echo -e "\033[1;31m[!] WARNING: Run Option 7 to apply changes to live firewall!\033[0m"
            read -p "Press [Enter] to continue..."
            ;;
        6)
            read -p "CONFIRM RESET: Open ALL ports and erase saved config? (y/n): " konfirmasi
            if [[ "$konfirmasi" == "y" || "$konfirmasi" == "Y" ]]; then
                cat << 'EOF' > "$NFT_CONF"
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy accept;
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF
                nft -f "$NFT_CONF"

                PUBLIC_PORTS=""
                RESTRICTED_RULES=""
                save_config

                echo "[+] Firewall reset complete. All rules set to ACCEPT (All ports opened)."
                sleep 2
            fi
            ;;
        7)
            apply_rules
            read -p "Press [Enter] to continue..."
            ;;
        8)
            clear
            echo "=== CURRENT ACTIVE NFTABLES RULESET ==="
            nft list ruleset
            echo "======================================="
            read -p "Press [Enter] to continue..."
            ;;
        9)
            echo "Exiting."
            exit 0
            ;;
        *)
            echo "Invalid selection!"
            sleep 1
            ;;
    esac
done
