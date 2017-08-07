#!/bin/bash

DIRB443SHOTS="$(cat /usr/share/sniper/loot/workspace/sixHostTest/notes/dirbExt_192.168.18.135/dirbFoundFiles_192.168.18.135.txt)"
if [ -n "$DIRB443SHOTS" ]; then
	echo -e "$OKGREEN + -- ----------------------------=[Making Screenshots of txt, php, and html Files In Found Directories]=----------- -- +$RESET"
	LIST_OF_URLS="$(cat /usr/share/sniper/loot/workspace/sixHostTest/notes/dirbExt_192.168.18.135/dirbFoundFiles_192.168.18.135.txt)"
	echo $LIST_OF_URLS
	for a in $LIST_OF_URLS ; do cutycapt --url=$a --out=/usr/share/sniper/loot/screenshots/$(echo $a | sed -e 's/\//_/g')_192.168.18.135_.jpg; done;
	find /usr/share/sniper/loot/screenshots/ -size -10k -exec rm -f {} \; 2> /dev/null
else
	echo -e "$OKORANGE + No Files Found by Dirb +$RESET"
fi
