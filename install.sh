#!/bin/bash

# Pentesting Tools Installer Script
set -e  # Exit on error

# Color definitions - more vibrant like linpeas
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Bright colors for emphasis
BRIGHT_RED='\033[38;5;196m'
BRIGHT_GREEN='\033[38;5;46m'
BRIGHT_YELLOW='\033[38;5;226m'
BRIGHT_BLUE='\033[38;5;33m'
BRIGHT_PURPLE='\033[38;5;129m'
BRIGHT_CYAN='\033[38;5;51m'

# Icons
STAR='★'
CHECK='✓'
WARNING='⚠'
ERROR='✗'
INFO='ⓘ'
ARROW='➜'
DOT='•'

# Print with colors and icons
print_banner() {
    clear
    echo -e "${BRIGHT_PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo -e "║   ${BRIGHT_YELLOW}${STAR} ${BRIGHT_CYAN}PENTESTING TOOLS INSTALLER ${STAR}${BRIGHT_PURPLE}                             ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${BRIGHT_GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BRIGHT_CYAN}$1${NC}"
    echo -e "${BRIGHT_GREEN}══════════════════════════════════════════════════════════════${NC}"
}

print_info() {
    echo -e "${BRIGHT_BLUE}[${INFO}]${NC} ${BRIGHT_BLUE}$1${NC}"
}

print_success() {
    echo -e "${BRIGHT_GREEN}[${CHECK}]${NC} ${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${BRIGHT_YELLOW}[${WARNING}]${NC} ${YELLOW}$1${NC}"
}

print_error() {
    echo -e "${BRIGHT_RED}[${ERROR}]${NC} ${RED}$1${NC}"
}

print_item() {
    echo -e "  ${BRIGHT_YELLOW}${DOT}${NC} ${CYAN}$1${NC}"
}

print_subitem() {
    echo -e "    ${BRIGHT_PURPLE}${ARROW}${NC} ${PURPLE}$1${NC}"
}

print_code() {
    echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}$1${NC}"
}

print_star_line() {
    echo -e "${BRIGHT_YELLOW}"
    echo "✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰"
    echo -e "${NC}"
}

# Show minimal progress
show_progress() {
    echo -n -e "${BRIGHT_BLUE}[${INFO}]${NC} ${BRIGHT_BLUE}$1...${NC}"
}

show_progress_done() {
    echo -e "\r${BRIGHT_GREEN}[${CHECK}]${NC} ${GREEN}$1 ✓${NC}"
}

# Start installation
print_banner
echo -e "${BRIGHT_YELLOW}Installing pentesting tools. Please wait...${NC}"
echo ""

# Run all installations silently
{
    # Update and install system packages
    sudo apt update > /dev/null 2>&1
    sudo apt install -y python3-scrapy python3-requests-ntlm libsasl2-dev libldap2-dev python3-pyftpdlib > /dev/null 2>&1
    
    # Install uv
    curl -LsSf https://astral.sh/uv/install.sh | sh > /dev/null 2>&1
    
    # Add uv to PATH
    export PATH="$HOME/.cargo/bin:$PATH"
    
    # Install tools via uv
    uv tool install impacket > /dev/null 2>&1
    sudo apt remove -y netexec 2>/dev/null || true
    uv tool install git+https://github.com/Pennyw0rth/NetExec > /dev/null 2>&1
    uv tool install git+https://github.com/dirkjanm/BloodHound.py.git@bloodhound-ce > /dev/null 2>&1
    uv tool install --with setuptools certipy-ad > /dev/null 2>&1
    uv tool install certipy-ad==5.0.4 > /dev/null 2>&1
    uv tool install evil-winrm-py==1.5.0 > /dev/null 2>&1
    uv tool install --python 3.13 git+https://github.com/CravateRouge/bloodyAD > /dev/null 2>&1
    
    # Clone and install from repository
    git clone https://github.com/boboaung1337/again.git > /dev/null 2>&1
    cd again
    
    # Install scripts with dependencies and copy to /usr/local/bin
    scripts=(
        "git-dumper.py"
        "windapsearch.py"
        "keytabextract.py"
        "getnthash.py"
        "gets4uticket.py"
        "gettgtpkinit.py"
        "firepwd.py"
    )
    
    for script in "${scripts[@]}"; do
        if [ -f "$script" ]; then
            uv add --script "$script" -r requirements.txt > /dev/null 2>&1
            
            if [[ "$script" == "git-dumper.py" ]]; then
                sudo cp "$script" /usr/local/bin/git-dumper
                sudo chmod +x /usr/local/bin/git-dumper
            elif [[ "$script" == "windapsearch.py" ]]; then
                sudo cp "$script" /usr/local/bin/windapsearch.py
                sudo chmod +x /usr/local/bin/windapsearch.py
            elif [[ "$script" == "keytabextract.py" ]]; then
                sudo cp "$script" /usr/local/bin/keytabextract.py
                sudo chmod +x /usr/local/bin/keytabextract.py
            elif [[ "$script" == "firepwd.py" ]]; then
                sudo cp "$script" /usr/local/bin/firepwd.py
                sudo chmod +x /usr/local/bin/firepwd.py
            else
                sudo cp "$script" /usr/local/bin/
                sudo chmod +x "/usr/local/bin/$script"
            fi
        fi
    done
    
    # Install additional scripts
    additional_scripts=(
        "winrmexec.py"
        "smbpasswd.py"
        "ntlm_theft.py"
        "ntlm_passwordspray.py"
        "ReconSpider.py"
        "targetedKerberoast.py"
        "pywhisker.py"
        "evil_winrmexec.py"
    )
    
    for script in "${additional_scripts[@]}"; do
        if [ -f "$script" ]; then
            sudo cp "$script" /usr/local/bin/
            sudo chmod +x "/usr/local/bin/$script"
            
            # Fix line endings for specific scripts
            if [[ "$script" =~ ^(smbpasswd|ntlm_theft|ReconSpider|targetedKerberoast|pywhisker|evil_winrmexec)\.py$ ]]; then
                sudo sed -i '1s/\r//' "/usr/local/bin/$script" > /dev/null 2>&1
            fi
        fi
    done
    
    # Cleanup
    cd ..
    rm -rf again
} &

# Show progress spinner
PID=$!
SPIN='⣷⣯⣟⡿⢿⣻⣽⣾'
i=0
while kill -0 $PID 2>/dev/null; do
    i=$(( (i+1) % 8 ))
    printf "\r${BRIGHT_BLUE}[${SPIN:$i:1}]${NC} Installing tools... Please wait"
    sleep 0.1
done

wait $PID

# Clear screen and show only final results
clear

# Directly show the summary without headers
echo -e "${BRIGHT_GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo -e "║          ${BRIGHT_YELLOW}${STAR} ${BRIGHT_CYAN}INSTALLATION SUCCESSFUL ${STAR}${BRIGHT_GREEN}                         ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo ""
echo -e "${BRIGHT_CYAN}INSTALLED TOOLS${NC}"
echo -e "${BRIGHT_GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BRIGHT_YELLOW}Main Tools (in /usr/local/bin/):${NC}"
echo -e "  ${CYAN}• git-dumper${NC}"
echo -e "  ${CYAN}• windapsearch.py${NC}"
echo -e "  ${CYAN}• keytabextract.py${NC}"
echo -e "  ${CYAN}• getnthash.py${NC}"
echo -e "  ${CYAN}• gets4uticket.py${NC}"
echo -e "  ${CYAN}• gettgtpkinit.py${NC}"
echo -e "  ${CYAN}• firepwd.py${NC}"
echo -e "  ${CYAN}• winrmexec.py${NC}"
echo -e "  ${CYAN}• smbpasswd.py${NC}"
echo -e "  ${CYAN}• ntlm_theft.py${NC}"
echo -e "  ${CYAN}• ntlm_passwordspray.py${NC}"
echo -e "  ${CYAN}• ReconSpider.py${NC}"
echo -e "  ${CYAN}• targetedKerberoast.py${NC}"
echo -e "  ${CYAN}• pywhisker.py${NC}"
echo -e "  ${CYAN}• evil_winrmexec.py${NC}"

echo ""
echo -e "${BRIGHT_YELLOW}UV Package Manager Tools:${NC}"
echo -e "  ${CYAN}• Impacket${NC}"
echo -e "  ${CYAN}• NetExec${NC}"
echo -e "  ${CYAN}• BloodHound.py${NC}"
echo -e "  ${CYAN}• Certipy-AD (v5.0.4)${NC}"
echo -e "  ${CYAN}• Evil-WinRM (v1.5.0)${NC}"
echo -e "  ${CYAN}• bloodyAD${NC}"

echo ""
echo -e "${BRIGHT_GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BRIGHT_CYAN}USAGE EXAMPLES${NC}"
echo -e "${BRIGHT_GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BRIGHT_PURPLE}Git Tools:${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}git-dumper -h${NC}"

echo -e "\n${BRIGHT_PURPLE}Active Directory Tools:${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}windapsearch.py -h${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}keytabextract.py carlos.keytab${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}keytabextract.py svc_workstations._all.kt${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}getnthash.py -h${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}gets4uticket.py -h${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}gettgtpkinit.py -h${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}smbpasswd.py -h${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}targetedKerberoast.py -h${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}pywhisker.py -h${NC}"

echo -e "\n${BRIGHT_PURPLE}Credential Tools:${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}firepwd.py -h${NC}"
echo -e "    ${PURPLE}➜ ${YELLOW}Firefox Credential Files:${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}key4.db        # Firefox key database${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}logins.json    # Firefox saved logins${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}cert9.db       # Firefox certificate database${NC}"
echo -e "    ${PURPLE}➜ ${YELLOW}Firefox Password Extraction:${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}firepwd.py key4.db${NC}"

echo -e "\n${BRIGHT_PURPLE}NTLM Tools:${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}ntlm_theft.py -h${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}ntlm_passwordspray.py -h${NC}"

echo -e "\n${BRIGHT_PURPLE}Reconnaissance:${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}ReconSpider.py -h${NC}"

echo -e "\n${BRIGHT_PURPLE}WinRM Tools:${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}winrmexec.py -h${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}evil_winrmexec.py -h${NC}"

echo ""
echo -e "${BRIGHT_GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BRIGHT_CYAN}QUICK START${NC}"
echo -e "${BRIGHT_GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BRIGHT_YELLOW}★ All tools are available in ${BRIGHT_CYAN}/usr/local/bin/${BRIGHT_YELLOW}"
echo -e "${BRIGHT_YELLOW}★ Use ${BRIGHT_RED}-h${BRIGHT_YELLOW} or ${BRIGHT_RED}--help${BRIGHT_YELLOW} with any tool for detailed usage"
echo ""
echo -e "${BRIGHT_CYAN}Example:${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}git-dumper --help${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}windapsearch.py --help${NC}"
echo -e "    ${BRIGHT_RED}\$${NC} ${BRIGHT_CYAN}keytabextract.py --help${NC}"

echo ""
echo -e "${BRIGHT_YELLOW}✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰${NC}"
echo -e "${BRIGHT_YELLOW}★ ${BRIGHT_CYAN}Happy Hacking! ${STAR}${NC}"
echo -e "${BRIGHT_YELLOW}✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰✰${NC}"
echo -e "${NC}"
