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

		echo -e "$OKGREEN + -- ----------------------------=[Running Directory Brute Force]=----------- -- +$RESET"
		mkdir $LOOT_DIR/notes/
		dirb http://$TARGET:$MODE /usr/share/wordlists/dirb/big.txt -o $LOOT_DIR/notes/dirb_out_"$TARGET"_"$MODE".txt -S
		rm -rf $LOOT_DIR/notes/dirb_directories_"$TARGET"_"$MODE".txt
		rm -rf $LOOT_DIR/notes/dirbExt_"$TARGET"_"$MODE"
		cat $LOOT_DIR/notes/dirb_out_"$TARGET"_"$MODE".txt | grep "==>" | cut -f3 -d ' ' > $LOOT_DIR/notes/dirb_directories_"$TARGET"_"$MODE".txt
		DIRBDIR="$(cat $LOOT_DIR/notes/dirb_directories_"$TARGET"_"$MODE".txt)"
		if [ -n "$DIRBDIR" ]; then
			echo -e "$OKGREEN + -- ----------------------------=[Finding txt, php, and html Files In Directories]=----------- -- +$RESET"
			mkdir $LOOT_DIR/notes/dirbExt_"$TARGET"_"$MODE"
			for a in `cat $LOOT_DIR/notes/dirb_directories_"$TARGET"_"$MODE".txt`; do dirb $a /usr/share/wordlists/dirb/big.txt -X .txt,.php,.html,.conf,.config -o $LOOT_DIR/notes/dirbExt_"$TARGET"_"$MODE"/$(echo $a | sed -e 's/\//_/g').txt -S; done;
			cat $LOOT_DIR/notes/dirbExt_"$TARGET"_"$MODE"/*.txt | grep "+" | cut -d " " -f2 > $LOOT_DIR/notes/dirbExt_"$TARGET"_"$MODE"/dirbFoundFiles_"$TARGET"_"$MODE".txt
			cat $LOOT_DIR/notes/dirb_out_"$TARGET"_"$MODE".txt | grep "+" | cut -f2 -d ' ' >> $LOOT_DIR/notes/dirbExt_"$TARGET"_"$MODE"/dirbFoundFiles_"$TARGET"_"$MODE".txt
			cat $LOOT_DIR/notes/dirb_out_"$TARGET"_"$MODE".txt | grep -B 1 "LISTABLE" | cut -f4 -d ' ' | grep -v "IS" | grep -v "\-\-" > $LOOT_DIR/notes/dirb_listable_directories_"$TARGET"_"$MODE".txt

			DIRBFF="$(cat "$LOOT_DIR"/notes/dirb_listable_directories_"$TARGET"_"$MODE".txt)"
			if [ -n "$DIRBFF" ]; then
				echo -e "$OKORANGE + Opening FireFox with Listable Directories found by Dirb +$RESET"
				xargs -a "$LOOT_DIR"/notes/dirb_listable_directories_"$TARGET"_"$MODE".txt firefox -new-tab "$line"
				echo -e "$OKORANGE + Opened FireFox with Listable Directories found by Dirb +$RESET"
			else
				echo -e "$OKORANGE + No Listable Directories found by Dirb +$RESET"
			fi



			DIRBSHOTS="$(cat $LOOT_DIR/notes/dirbExt_"$TARGET"_"$MODE"/dirbFoundFiles_"$TARGET"_"$MODE".txt)"
			echo $DIRBSHOTS
			if [ -n "$DIRBSHOTS" ]; then
				echo -e "$OKGREEN + -- ----------------------------=[Making Screenshots of txt, php, and html Files In Found Directories]=----------- -- +$RESET"
				for a in `cat $LOOT_DIR/notes/dirbExt_"$TARGET"_"$MODE"/dirbFoundFiles_"$TARGET"_"$MODE".txt`; do cutycapt --url=$a --out=$LOOT_DIR/screenshots/$(echo $a | sed -e 's/\//_/g')"$TARGET"_"$MODE"_$(date +'%FT%H%M%S%3N')_.jpg; done;
				find $LOOT_DIR/screenshots/ -size -10k -exec rm -f {} \; 2> /dev/null
			else
				echo -e "$OKORANGE + No Files Found by Dirb +$RESET"
			fi
		else
			echo -e "$OKORANGE + No Directories Found by Dirb +$RESET"
		fi

		echo -e "$OKORANGE + Done with SniperDirb +$RESET"
		echo -e "$OKGREEN + -- ----------------------------=[Exiting Sniper sh script]=---- -- +$RESET"
		exit
