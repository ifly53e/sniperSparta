#!/bin/bash

#sparta should be already installed by default

#for kali download atom deb from atom.io then run
#apt install /root/Downloads/atom-amd64.deb

#to install sniper
#cd /root
#git clone https://github.com/1N3/Sn1per.git
#cd /root/Sn1per/sniper
#chmod +x install.sh
#./install.sh

#apt-get update && upgrade -y

#make sure sniper is installed first or this won't work
echo "replacing sniper"
mv /usr/share/sniper/sniper /usr/share/sniper/sniper_$(date +'%FT%H%M%S%3N')
cp ./sniper /usr/share/sniper/

#make sure sparta is installed first or this won't work
echo "replacing sparta.conf"
mv /usr/share/sparta/sparta.conf /usr/share/sparta/sparta.conf_$(date +'%FT%H%M%S%3N')
cp ./sparta.conf /usr/share/sparta/

#make sure sparta is installed first or this won't work
echo "copying sparta scripts folder"
mv /usr/share/sparta/scripts/ /usr/share/sparta/scripts_$(date +'%FT%H%M%S%3N')/
cp -r ./scripts /usr/share/sparta/

#make sure atom language-ansi package is installed first or this won't work
echo "replacing atom ansi.cson"
mv /root/.atom/packages/language-ansi/grammars/ansi.cson /root/.atom/packages/language-ansi/grammars/ansi.cson_$(date +'%FT%H%M%S%3N')
cp ./ansi.cson /root/.atom/packages/language-ansi/grammars/ansi.cson

echo "replacing atom keymap.cson"
mv /root/.atom/keymap.cson /root/.atom/keymap.cson_$(date +'%FT%H%M%S%3N')
cp ./keymap.cson /root/.atom/keymap.cson

#for smb-psexec NSE script (will cause antivirus false positive)
echo "adding nmap_service.exe"
cp ./nmap_service.exe /usr/share/nmap/nselib/data/psexec/
cd /usr/share/nmap/nselib/data/psexec/
chmod +x nmap_service.exe

echo "done"
echo "open sparta and enter an IP to scan..."
