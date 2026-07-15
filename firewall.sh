#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run this script as ROOT (sudo)!"
    exit 1
fi

# =======================================================
# 1. OS DETECTION & AUTO-INSTALL DEPENDENCIES
# =======================================================
detect_and_setup_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$ID
        OS_VERSION=$VERSION_ID
    else
        echo "[!] OS not detected."
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
# 2. PERSISTENT CONFIGURATION MANAGEMENT
# =======================================================
CONFIG_FILE="/etc/manage-fw.conf"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    PUBLIC_PORTS=""
    RESTRICTED_RULES=""
fi

save_config() {
    # Pastikan variabel bersih dari spasi tak berguna sebelum disimpan
    PUBLIC_PORTS=$(echo "$PUBLIC_PORTS" | tr -s ' ' | sed -e 's/^[ \t]*//;s/[ \t]*$//')
    RESTRICTED_RULES=$(echo "$RESTRICTED_RULES" | tr -s ' ' | sed -e 's/^[ \t]*//;s/[ \t]*$//')
    echo "PUBLIC_PORTS=\"$PUBLIC_PORTS\"" > "$CONFIG_FILE"
    echo "RESTRICTED_RULES=\"$RESTRICTED_RULES\"" >> "$CONFIG_FILE"
}

# =======================================================
# 3. IPTABLES CORE ENGINE
# =======================================================
apply_rules() {
    echo -e "\n[+] Flushing existing rules and applying new configuration..."
    iptables -F
    iptables -X
    iptables -Z
    
    # Default Policy
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # State tracking via modern conntrack module
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    
    # Allow ICMP (Ping) and Loopback interface
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    
    # Allow forwarding for VPN virtual interfaces
    iptables -A FORWARD -i tun+ -j ACCEPT
    iptables -A FORWARD -i wg+ -j ACCEPT
    iptables -A FORWARD -i ppp+ -j ACCEPT

    # Pengecekan agar tidak memproses rule kosong
    local check_rules=$(echo "$RESTRICTED_RULES" | tr -d ' ')
    if [ ! -z "$check_rules" ]; then
        echo "[+] Applying Granular Whitelist Rules..."
        local restricted_ports=$(echo "$RESTRICTED_RULES" | tr ' ' '\n' | cut -d':' -f1 | sort -u | tr '\n' ' ')
        
        for rule in $RESTRICTED_RULES; do
            local port=$(echo "$rule" | cut -d':' -f1)
            local ip=$(echo "$rule" | cut -d':' -f2)
            if [ ! -z "$port" ] && [ ! -z "$ip" ]; then
                iptables -A INPUT -p tcp -s "$ip" --dport "$port" -j ACCEPT
                iptables -A INPUT -p udp -s "$ip" --dport "$port" -j ACCEPT
                echo "    -> [ACCEPT] Source: $ip -> Destination Port: $port (TCP/UDP)"
            fi
        done
        
        for r_port in $restricted_ports; do
            if [ ! -z "$r_port" ]; then
                iptables -A INPUT -p tcp --dport "$r_port" -j DROP
                iptables -A INPUT -p udp --dport "$r_port" -j DROP
                echo "    -> [DROP] Destination Port: $r_port (Global/Public)"
            fi
        done
        
        # Global catch-all block for restricted zones
        iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
        iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited
    fi
    
    echo "[+] Opening Public Ports..."
    for port in $PUBLIC_PORTS; do
        if [ ! -z "$port" ] && [[ "$port" =~ ^[0-9]+$ ]]; then
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT
            echo "    -> [ACCEPT] Destination Port: $port (Any Source)"
        fi
    done
    
    echo "[+] Saving rules to system storage..."
    eval $SAVE_COMMAND > /dev/null 2>&1
    echo "[+] Success: All firewall rules deployed and persistent."
}

show_status() {
    clear
    echo "========================================================="
    echo "         DYNAMIC GRANULAR FIREWALL MANAGER v3.9          "
    echo "========================================================="
    echo "  [PUBLIC OPEN PORTS (TCP/UDP)]"
    if [ -z "$PUBLIC_PORTS" ] || [ "$PUBLIC_PORTS" == " " ]; then
        echo "  -> (None)"
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
    echo "2) Add public (to) open ports (comma or space separated)"
    echo "3) Remove (to close / disabled) public open ports "
    echo "4) Add (to open) port rule (restrict port to specific IP/Subnet)"
    echo "5) Remove (to close) port rule"
    echo "6) Disable firewall completely (Flush and accept all)"
    echo "7) Apply and save active rules"
    echo "8) View live running iptables rules"
    echo "9) Exit"
    read -p "Enter selection [1-9]: " opsi

    case $opsi in
        1)
            echo -e "\n[+] Scanning system for active listening ports..."
            if command -v ss &> /dev/null; then
                detected_list=$(ss -tulpn | tr -s ' ' | grep -vi "peer" | sed -E 's/users:\(\(.*//g' | grep -oE ':[0-9]+ ' | tr -d ': ' | sort -n -u | tr '\n' ' ')
            else
                detected_list=$(netstat -tulpn | tr -s ' ' | grep -i "listen" | awk '{print $4}' | awk -F':' '{print $NF}' | sort -n -u | tr '\n' ' ')
            fi

            detected_list=$(echo "$detected_list" | sed -E 's/\b(0)\b//g' | tr -s ' ')

            if [ -z "$detected_list" ] || [ "$detected_list" == " " ] || [ "$detected_list" == "" ]; then
                echo "[!] No active listening ports detected."
                sleep 2
            else
                comma_view=$(echo "$detected_list" | tr ' ' ',' | sed 's/,$//' | sed 's/^,//')
                echo -e "-> Detected active ports: \033[1;32m$comma_view\033[0m"
                
                read -p "Add ALL detected ports to the public list? (y/n): " konfirmasi
                if [[ "$konfirmasi" == "y" || "$konfirmasi" == "Y" ]]; then
                    if [[ "$PUBLIC_PORTS" == *"Firewall Disabled"* ]]; then
                        PUBLIC_PORTS=""
                    fi
                    
                    for p_detect in $detected_list; do
                        if [[ ! " $PUBLIC_PORTS " =~ " $p_detect " ]]; then
                            PUBLIC_PORTS="$PUBLIC_PORTS $p_detect"
                        fi
                    done
                    
                    save_config
                    echo "[+] Ports imported to temporary list. Run Option 7 to apply changes."
                    sleep 2
                else
                    echo "[!] Operation cancelled."; sleep 1
                fi
            fi
            ;;
        2)
            read -p "Enter new public ports (e.g., 80,443,3000 or 80 443 3000): " input_ports
            cleaned_ports=$(echo "$input_ports" | tr ',' ' ' | tr -s ' ')
            if [[ "$PUBLIC_PORTS" == *"Firewall Disabled"* ]]; then PUBLIC_PORTS=""; fi

            any_valid=false
            for port in $cleaned_ports; do
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                    if [[ ! " $PUBLIC_PORTS " =~ " $port " ]]; then
                        PUBLIC_PORTS="$PUBLIC_PORTS $port"
                    fi
                    any_valid=true
                else
                    echo "[!] Invalid port '$port' (not an integer), skipping."
                fi
            done
            save_config
            if [ "$any_valid" = true ]; then
                echo "[+] Ports added to temporary list. Run Option 7 to apply changes."; sleep 2
            else
                echo "[!] No valid ports entered."; sleep 1.5
            fi
            ;;
        3)
            read -p "Enter public ports to remove (comma or space separated): " del_ports
            cleaned_del=$(echo "$del_ports" | tr ',' ' ' | tr -s ' ')
            for port in $cleaned_del; do
                PUBLIC_PORTS=$(echo " $PUBLIC_PORTS " | sed -e "s| $port ||g")
            done
            save_config
            echo "[+] Ports removed from temporary list. Run Option 7 to apply changes."
            sleep 2
            ;;
        4)
            read -p "Enter port number to restrict (e.g., 53, 3306): " g_port
            read -p "Enter allowed IP/Subnet (e.g., 1.1.1.1 or 10.0.0.0/24): " g_ip
            if [ ! -z "$g_port" ] && [ ! -z "$g_ip" ]; then
                # Membersihkan spasi tak sengaja pada input
                g_port=$(echo "$g_port" | tr -d ' ')
                g_ip=$(echo "$g_ip" | tr -d ' ')
                
                new_rule="$g_port:$g_ip"
                if [[ ! " $RESTRICTED_RULES " =~ " $new_rule " ]]; then
                    RESTRICTED_RULES="$RESTRICTED_RULES $new_rule"
                fi
                save_config
                echo "[+] Rule added to temporary list. Run Option 7 to apply changes."
                sleep 2
            fi
            ;;
        5)
            echo "Enter the exact 'PORT:IP' format to remove as listed in the status above."
            read -p "Enter target rule (e.g., 53:1.1.1.1): " del_rule
            
            if [ ! -z "$del_rule" ]; then
                # Hapus spasi di input agar pencocokan akurat
                del_rule=$(echo "$del_rule" | tr -d ' ')
                
                # Menggunakan [^ ]* untuk menyapu bersih karakter ekor tak dikenal (seperti :n atau lainnya)
                RESTRICTED_RULES=$(echo " $RESTRICTED_RULES " | sed -E "s| $del_rule[^ ]* ||g" -e 's/  */ /g')
                save_config
                echo -e "\033[1;32m[+] Rule successfully cleared from the configuration file.\033[0m"
            else
                echo "[!] No input provided."
            fi
            
            echo -e "\033[1;31m[!] WARNING: You MUST run Option 7 to apply this to the live firewall!\033[0m"
            read -p "Press [Enter] to continue..."
            ;;
        6)
            read -p "Are you sure you want to flush all rules and open all ports? (y/n): " konfirmasi
            if [[ "$konfirmasi" == "y" || "$konfirmasi" == "Y" ]]; then
                iptables -F
                iptables -X
                iptables -Z
                iptables -P INPUT ACCEPT
                iptables -P FORWARD ACCEPT
                iptables -P OUTPUT ACCEPT
                eval $SAVE_COMMAND > /dev/null 2>&1
                
                PUBLIC_PORTS="Firewall Disabled (ACCEPT ALL)"
                RESTRICTED_RULES=""
                save_config
                echo "[+] Firewall flushed. All targets set to ACCEPT."
                sleep 2
            fi
            ;;
        7)
            if [[ "$PUBLIC_PORTS" == *"Firewall Disabled"* ]]; then
                PUBLIC_PORTS=""
            fi
            apply_rules
            read -p "Press [Enter] to continue..."
            ;;
        8)
            clear
            echo "=== CURRENT ACTIVE IPTABLES RULES ==="
            iptables -L -n -v --line-numbers
            echo "====================================="
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
