#!/bin/bash
###############################################################
#Name: Michael White     lecturer's name: Natalie             #
#Magen773623:s14:Penetration Testing                           #
#                                                             #  
#sites used >                                                 #
#https://chat.openai.com                                      #     
#https://ansi.gabebanks.net/                                  #
#https://gabebanks.net/                                       #
#https://ipapi.co/                                            #
#https://www.baeldung.com/linux/run-shell-script-remote-ssh   #
###############################################################
# Reset-color
Color_Off='\033[0m'       # Text Reset
# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White

# Bold
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White

# ASCII Logo
function display_logo() {
    echo -e "${Red} _____ ______   ___  ________  ___  ___  ________  _______   ___               ___       __   ___  ___  ___  _________  _______      "
    echo -e "${Red}|\   _ \  _   \|\  \|\   ____\|\  \|\  \|\   __  \|\  ___ \ |\  \             |\  \     |\  \|\  \|\  \|\  \|\___   ___\\  ___ \     "
    echo -e "${Red}\ \  \\\__\ \  \ \  \ \  \___|\ \  \\\  \ \  \|\  \ \   __/|\ \  \            \ \  \    \ \  \ \  \\\  \ \  \|___ \  \_\ \   __/|    "
    echo -e "${Red} \ \  \\|__| \  \ \  \ \  \    \ \   __  \ \   __  \ \  \_|/_\ \  \            \ \  \  __\ \  \ \   __  \ \  \   \ \  \ \ \  \_|/__  "
    echo -e "${Red}  \ \  \    \ \  \ \  \ \  \____\ \  \ \  \ \  \ \  \ \  \_|\ \ \  \____        \ \  \|\__\_\  \ \  \ \  \ \  \   \ \  \ \ \  \_|\ \ "
    echo -e "${Red}   \ \__\    \ \__\ \__\ \_______\ \__\ \__\ \__\ \__\ \_______\ \_______\       \ \____________\ \__\ \__\ \__\   \ \__\ \ \_______\\"
    echo -e "${Red}    \|__|     \|__|\|__|\|_______|\|__|\|__|\|__|\|__|\|_______|\|_______|        \|____________|\|__|\|__|\|__|    \|__|  \|_______|"
    echo -e "${Red}                                                                                                                                     "
    echo -e "${Red}    Network vulnerability Scan By Michael White                                                                                                                                 "
    echo -e "${Color_Off}"  # Reset color after the logo
}

# Display the logo
display_logo

# Global Variables
password_list="/usr/share/wordlists/rockyou.txt"  # Default password list
user_flag=""
output_dir=""
mode=""
network=""

# Functions
function validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        echo -e "${BRed}Invalid IP address. Please enter a valid network.${Color_Off}"
        exit 1
    fi
}

function check_tools_installed() {
    tools=("nmap" "medusa" "searchsploit" "zip")

    for tool in "${tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${BRed}Error: $tool is not installed. Please install it and rerun the script.${Color_Off}"
            exit 1
        fi
    done
    echo -e "${BGreen}All required tools are installed!${Color_Off}"
}

function get_user_input() {
    read -p "Enter the network to scan (e.g., 192.168.1.0/24): " network
    validate_ip $network

    read -p "Enter a name for the output directory: " output_dir
    mkdir -p $output_dir

    echo "Choose scan mode:"
    echo "1) Basic"
    echo "2) Full"
    read -p "Enter the option (1 or 2): " mode_choice

    case $mode_choice in
        1) mode="Basic" ;;
        2) mode="Full" ;;
        *) echo -e "${BRed}Invalid choice. Exiting.${Color_Off}"; exit 1 ;;
    esac

    echo -e "${BGreen}Scan mode selected: $mode${Color_Off}"

    echo "Do you want to use a single user or a user list for weak password checks?"
    echo "1) Single user"
    echo "2) User list"
    read -p "Enter the option (1 or 2): " user_choice

    if [[ "$user_choice" == "1" ]]; then
        read -p "Enter the username: " single_user
        user_flag="-u $single_user"
        echo -e "${BGreen}Single user mode selected: $single_user${Color_Off}"
    elif [[ "$user_choice" == "2" ]]; then
        read -p "Enter the path to your user list: " user_list
        user_flag="-U $user_list"
        echo -e "${BGreen}User list mode selected: $user_list${Color_Off}"
    else
        echo -e "${BRed}Invalid choice. Exiting.${Color_Off}"
        exit 1
    fi

    echo "Do you want to use a custom password list? (y/n)"
    read custom_password_list_choice
    if [[ "$custom_password_list_choice" == "y" ]]; then
        read -p "Enter the path to your custom password list: " password_list
    fi

    # Check if the password file exists
    if [[ ! -f $password_list ]]; then
        echo -e "${BRed}Error: Password list file '$password_list' not found.${Color_Off}"
        exit 1
    fi
    echo -e "${BGreen}Password list: $password_list${Color_Off}"
}

function scan_network() {
    echo -e "${BYellow}[*] Scanning the network ($network) in $mode mode...${Color_Off}"
    if [[ $mode == "Basic" ]]; then
        sudo nmap -sT -sU -sV -oN $output_dir/nmap_basic_scan.txt $network  > /dev/null 2>&1
    elif [[ $mode == "Full" ]]; then
        sudo nmap -sT -sU -sV --script vuln -oN $output_dir/nmap_full_scan.txt $network  > /dev/null 2>&1
    fi

    if [[ $? -ne 0 ]]; then
        echo -e "${BRed}Nmap scan failed. Retrying...${Color_Off}"
        scan_network
    else
        echo -e "${BGreen}Network scan completed successfully!${Color_Off}"
    fi
}

function detect_services() {
    echo -e "${BYellow}[*] Detecting running services from the scan results...${Color_Off}"
    detected_services=()

    if grep -q '22/tcp' $output_dir/nmap_*_scan.txt; then
        detected_services+=("ssh")
    fi
    if grep -q '3389/tcp' $output_dir/nmap_*_scan.txt; then
        detected_services+=("rdp")
    fi
    if grep -q '21/tcp' $output_dir/nmap_*_scan.txt; then
        detected_services+=("ftp")
    fi
    if grep -q '23/tcp' $output_dir/nmap_*_scan.txt; then
        detected_services+=("telnet")
    fi

    if [[ ${#detected_services[@]} -eq 0 ]]; then
        echo -e "${BPurple}No relevant services detected for weak password checks.${Color_Off}"
    else
        echo -e "${BGreen}[*] Detected services: ${detected_services[*]}${Color_Off}"
    fi
}

function check_weak_passwords() {
    if [[ ${#detected_services[@]} -eq 0 ]]; then
        echo -e "${BPurple}Skipping weak password checks due to no relevant services detected.${Color_Off}"
        return
    fi

    echo -e "${BYellow}[*] Checking for weak passwords...${Color_Off}"

    for service in "${detected_services[@]}"; do
        echo -e "${BYellow}[*] Checking for weak passwords on $service...${Color_Off}"
        
        # Use Medusa for brute-force with single user or user list
        if [[ $service == "ssh" || $service == "ftp" || $service == "telnet" ]]; then
            sudo medusa -h $network $user_flag -P $password_list -M $service -t 32 -T 6 -f > $output_dir/medusa_$service.txt
        fi

        if [[ $? -ne 0 ]]; then
            echo -e "${BRed}Medusa failed for $service. Retrying...${Color_Off}"
            sudo medusa -h $network $user_flag -P $password_list -M $service -t 32 -T 6 -f > $output_dir/medusa_$service.txt
        fi
    done
}

function map_vulnerabilities() {
    if [[ $mode == "Full" ]]; then
        echo -e "${BYellow}[*] Running vulnerability analysis using Searchsploit...${Color_Off}"
        searchsploit --nmap $output_dir/nmap_full_scan.txt > $output_dir/vulnerabilities.txt > /dev/null 2>&1
        
        if [[ $? -ne 0 ]]; then
            echo -e "${BRed}Searchsploit failed. Retrying...${Color_Off}"
            searchsploit --nmap $output_dir/nmap_full_scan.txt > $output_dir/vulnerabilities.txt > /dev/null 2>&1
        else
            echo -e "${BGreen}Vulnerability mapping completed!${Color_Off}"
        fi
    fi
}

function log_results() {
    echo -e "${BGreen}[*] Scan completed. Results saved in $output_dir.${Color_Off}"
    echo -e "${BYellow}[*] You can search through the results.${Color_Off}"
    grep -r '' $output_dir >> $output_dir/log.txt 2>&1
}

function zip_results() {
    echo -e "${BYellow}[*] Saving results to zip file...${Color_Off}"
    zip -r $output_dir.zip $output_dir > /dev/null 2>&1
    
    if [[ $? -ne 0 ]]; then
        echo -e "${BRed}Failed to zip results. Retrying...${Color_Off}"
        zip -r $output_dir.zip $output_dir > /dev/null 2>&1
    else
        echo -e "${BGreen}Results saved to $output_dir.zip${Color_Off}"
    fi
}

# Main Script Execution
check_tools_installed
get_user_input
scan_network
detect_services
check_weak_passwords
if [[ $mode == "Full" ]]; then
    map_vulnerabilities
fi
log_results
zip_results

echo -e "${BGreen}[*] Process completed! Results saved in $output_dir/log.txt${Color_Off}"
