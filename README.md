🛡️ Dynamic Firewall Manager (iptables)
📝 Quick Summary
This script is an interactive, menu-driven Bash tool designed to manage Linux firewall (iptables) rules easily and consistently. It allows you to open ports to the public or strictly restrict sensitive ports (like SSH or databases) to trusted IP addresses or subnets. It uses a Staging & Commit design, meaning changes are saved to a configuration file first and only applied to the live system when you choose to deploy them, preventing accidental lockouts.

✨ Features
Automated OS Deployment: Automatically detects your OS (Debian/Ubuntu or RHEL/AlmaLinux/Rocky) and installs required persistent firewall services so rules survive a system reboot.

Listening Port Auto-Scan: Scans your live server for active listening ports (ss or netstat) and allows you to whitelist them publicly in one click.

Granular Whitelisting: Restricts specific ports to designated IPs or subnets (e.g., allow port 3306 only for IP 192.168.1.50).

Smart Rule Deletion: Cleanly wipes configurations and eliminates common regex boundary bugs caused by dots (. ) or subnet slashes (/).

Staging Architecture: Keeps changes in a safe temporary state until you manually review and apply them live.

🚀 How to Use
1. Run the Script
The script manipulates kernel network tables, so it must be run as root:

Bash
chmod +x manage-fw.sh
sudo ./manage-fw.sh
2. Standard Workflow
Stage Changes: Use Options 1 to 5 to add or remove public ports and IP-restricted rules.

Commit Live: Select Option 7 (Apply and save active rules) to compile your changes and push them to the active firewall.

Verify: Use Option 8 to inspect the live running iptables rules directly from the kernel.

🤖 AI-Generated Notice
Notice: This utility was co-developed, refined, and optimized with the assistance of Artificial Intelligence (AI) to ensure secure shell scripting execution, proper string manipulation for IP addresses, and clean multi-distro dependency handling.
