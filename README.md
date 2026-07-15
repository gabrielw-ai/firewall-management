# 🛡️IP Tables Firewall Manager (Easy to Use)

## 📝 Quick Summary
This script is an interactive, menu-driven Bash tool designed to manage Linux firewall (`iptables`) rules easily and consistently. It allows you to open ports to the public or strictly restrict sensitive ports (like SSH or databases) to trusted IP addresses or subnets. 

It uses a **Staging & Commit** design, meaning changes are saved to a configuration file first and only applied to the live system when you choose to deploy them, preventing accidental lockouts.

---

## ✨ Features

* **Automated OS Deployment**: Automatically detects your OS (Debian/Ubuntu or RHEL/AlmaLinux/Rocky) and installs required persistent firewall services so rules survive a system reboot.
* **Listening Port Auto-Scan**: Scans your live server for active listening ports (`ss` or `netstat`) and allows you to whitelist them publicly in one click.
* **Custom Whitelisting**: Restricts specific ports to designated IPs or subnets (e.g., allow port `3306` only for IP `192.168.1.50`).
* **Smart Rule Deletion**: Cleanly wipes configurations and eliminates common regex boundary bugs caused by dots (`.`) or subnet slashes (`/`).
* **Staging Architecture**: Keeps changes in a safe temporary state until you manually review and apply them live.

---

## 🎛️ Menu Options Breakdown

* **Option 1: Auto-detect all listening ports and add to public list**
  Scans active network interfaces for services currently listening for traffic and batches them directly into your public allowances list.
* **Option 2: Add public open ports**
  Accepts a comma or space-separated list of ports to open up globally to any incoming source traffic.
* **Option 3: Remove public open ports**
  Allows you to disable port access.
* **Option 4: Add port rule (Whitelisting)**
  Tethers a specific destination port tightly to an exclusive incoming IP address or network subnet block.
* **Option 5: Remove port rule**
  Clears customized granular IP/Port configurations from the storage layer, stripping out any trailing garbage flags effortlessly.
* **Option 6: Disable firewall completely**
  Performs an emergency deployment dump: flushes all tables, deletes customizations, and sets the main structural chains (`INPUT`, `FORWARD`, `OUTPUT`) back to open `ACCEPT`.
* **Option 7: Apply and save active rules**
  The main compiler logic. Pulls staged parameters from `/etc/manage-fw.conf`, processes loopbacks, state management, and custom whitelists, and forces the live kernel tables to save state permanently.
* **Option 8: View live running iptables rules**
  Dumps the explicit verbose running kernel tables matched alongside relative rule line numbers for easy evaluation.
* **Option 9: Exit**
  Terminates the execution interface loop safely.
## 🚀 How to Use

### Run the Script
The script manipulates kernel network tables, so it **must be run as root**:

```bash
chmod +x firewall.sh
sudo ./firewall.sh
```

## 🤖 AI-Generated Notice

> **Notice:** This utility was co-developed, refined, and optimized with the assistance of Artificial Intelligence (AI) to ensure secure shell scripting execution, proper string manipulation for IP addresses, and clean multi-distro dependency handling.

