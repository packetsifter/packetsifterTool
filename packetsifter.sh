#!/usr/bin/env bash

#user supplied pcap from cli
pcap=$1

#header
printf '

 ____    ____     __  __  _    ___  ______       _____ ____  _____  ______    ___  ____  
|    \  /    |   /  ]|  |/ ]  /  _]|      |     / ___/|    ||     ||      |  /  _]|    \ 
|  o  )|  o  |  /  / |    /  /  [_ |      |    (   \_  |  | |   __||      | /  [_ |  D  )
|   _/ |     | /  /  |    \ |    _]|_|  |_|     \__  | |  | |  |_  |_|  |_||    _]|    / 
|  |   |  _  |/   \_ |     ||   [_   |  |       /  \ | |  | |   _]   |  |  |   [_ |    \ 
|  |   |  |  |\     ||  .  ||     |  |  |       \    | |  | |  |     |  |  |     ||  .  \
|__|   |__|__| \____||__|\_||_____|  |__|        \___||____||__|     |__|  |_____||__|\_|
                                                                                         
'

printf '\nFollow me on twitter @packetsifter\n'

#metadata about capture, print description
printf '\nMetadata about pcap is below\n'
capinfos $pcap

#input/output stats
tshark -nr $pcap -q -z io,stat,30 > IOstatistics.txt 2>>errors.txt
tshark -nr $pcap -q -z io,phs >> IOstatistics.txt 2>>errors.txt
printf '\n\n\n\nInput/Output statistics have been generated and are available in: IOstatistics.txt\n'
printf 'IOstatistics.txt contains Protocol Hierarchy and Input/Output broken up in 30 second intervals (useful to find potential beaconing)\n'

#IP Statistics
tshark -nr $pcap -q -z endpoints,ip > IPstatistics.txt 2>>errors.txt
tshark -nr $pcap -q -z conv,ip >> IPstatistics.txt 2>>errors.txt
printf '\n\n\nIP Statistics have been generated and are available in: IPstatistics.txt\n'
printf 'IPstatistics contains overall stats to/from endpoints over IP and individual conversations over IP\n'

#TCP Statistics
tshark -nr $pcap -q -z endpoints,tcp > TCPstatistics.txt 2>>errors.txt
tshark -nr $pcap -q -z conv,tcp >> TCPstatistics.txt 2>>errors.txt
printf '\n\n\nTCPstatistics have been generated and are available in: TCPstatistics.txt\n'
printf 'TCPstatistics contains overall stats to/from endpoints over TCP and individual TCP conversations broken down. <<Warning>> This file can contain a large amount of information. It is recommended to use less or grep for a conversation in question.\n'


#HTTP sifting time
printf '\n\n\n################# HTTP SIFTING #################\n\n'
tshark -nr $pcap -q -z http,tree > http_info.txt 2>>errors.txt
tshark -nr $pcap -q -z http_req,tree >> http_info.txt 2>>errors.txt
tshark -nr $pcap -q -z http_srv,tree >> http_info.txt 2>>errors.txt
printf '\nStatistical data about HTTP conversations have been generated and are available in: http_info.txt\n'

#empty http_info.txt check
httpcheck=$(cat http_info.txt | wc -l)
if [[ $httpcheck -eq 36 ]]; then
	rm http_info.txt
	printf '\nNo HTTP traffic found. Deleting arbitrary http_info.txt\n'
fi



#ask to resolve hostnames
printf '\nWould you like to resolve host names observed in pcap? This may take a long time depending on the pcap!!\n'
printf '<<Warning>> This can result in DNS queries for attacker infrastructure. Proceed with caution!!\n'
printf '(Please supply Y for yes or N for no)\n'
read hostnameAnswer

#if statement for host resolution
if [  $hostnameAnswer == 'Y' ] || [ $hostnameAnswer == 'y' ]
then
	tshark -nr $pcap -N Nnt -z hosts > deletethis.txt 2>>errors.txt
	cat deletethis.txt | grep '# TShark' -A 100000000 > hostnamesResolved.txt
	rm deletethis.txt
	printf '\nhostnamesResolved.txt contains resolved hostnames observed in pcap\n'
fi

#HTTP pcap carving
tshark -nr $pcap -n -Y '(tcp.port==80 || tcp.port==8080 || tcp.port==8000)' -w http.pcap 2>>errors.txt
printf '\nhttp.pcap contains all conversations containing port 80,8080,8000\n'

#empty http.pcap check
httppcapcheck=$(tshark -r http.pcap | wc -l)
if [[ $httppcapcheck -eq 0 ]]; then
	rm http.pcap
	printf 'No HTTP traffic found. Deleting arbitrary http.pcap\n'
fi


#prompt for user input to export
printf '\nWould you like to export HTTP objects? The objects will be outputted to a tarball in the current directory titled: httpObjects.tar.gz' 
printf '\n<<Warning>> There could be a lot of HTTP objects and you can potentially extract malicious http objects depending on the pcap. Use with caution!!\n'

printf '(Please supply Y for yes or N for no)\n'

#capture user input
read httpAnswer

#if statement to check if yes, then pull objects
if [ $httpAnswer == 'Y' ] || [ $httpAnswer == 'y' ]
then
	tshark -nr $pcap -q --export-objects http,./httpObjects 2>>errors.txt
	tar -czf httpObjects.tar.gz ./httpObjects
	rm -rf ./httpObjects

#HTTP Object Check
	httpobjectcheck=$(tar -xzvf httpObjects.tar.gz | wc -l)
	if [[ $httpobjectcheck -eq 1 ]]; then
		rm httpObjects.tar.gz
		rm -rf ./httpObjects
		printf '\nNo HTTP Objects found. Deleting arbitrary httpObjects.tar.gz.\n'
		rm -rf ./httpObjects
	else
#VirusTotal Integration HTTP
		printf '\nWould you like to lookup exported HTTP objects using VirusTotal?\n**Warning** You must have ran the VTinitial.sh script to initialize PacketSifter with your VirusTotal API Key.\n'
		printf '(Please supply Y for yes or N for no)\n'
		read VTHTTPLookup
			if [ $VTHTTPLookup == 'Y' ] | [ $VTHTTPLookup == 'y' ]
			then
				tar -xzf httpObjects.tar.gz
				for VAL in $(ls ./httpObjects)
				do
					md5sum ./httpObjects/$VAL >> ./httpHashToObject.txt
					cat httpHashToObject.txt | awk '{ print $1 }' | sort | uniq > lookup.txt
				done

				while read ARG
				do
					curl -s --request GET   --url https://www.virustotal.com/api/v3/files/$ARG  --header 'x-apikey: test' | jq '.data.attributes.md5, .data.attributes.last_analysis_stats, .error' | grep -E code\|[a-f0-9]{32}\|malicious\|undetected >> output.txt
				done < lookup.txt
				sed '/undetected/a\'$'\n'  output.txt > output2.txt 
				sed '/message/a\'$'\n' output2.txt > httpVTResults.txt
				rm -rf ./httpObjects
				rm lookup.txt
				rm output.txt
				rm output2.txt
			fi
	fi
	rm -rf ./httpObjects

fi



#SMB carving time
printf '\n\n\n################# SMB SIFTING #################\n\n'

printf '\nStats on commands ran using smb or smb2 has been generated and is available in: SMBstatistics.txt\n'
tshark -nr $pcap -q -z smb,srt > SMBstatistics.txt 2>>errors.txt
tshark -nr $pcap -q -z smb2,srt >> SMBstatistics.txt 2>>errors.txt

#smb statistics check
smbstatscheck=$(cat SMBstatistics.txt | wc -l)
if [[ $smbstatscheck -eq 18 ]]; then
	rm SMBstatistics.txt
	printf '\nNo SMB traffic found. Deleting arbitrary SMBstatistics.txt\n'
fi

printf 'smb.pcap contains all conversations categorized by tshark dissectors as NBSS, SMB, or SMB2\n'
tshark -nr $pcap -Y nbss -w smb.pcap 2>>errors.txt

#SMB pcap check
smbpcapcheck=$(tshark -r smb.pcap | wc -l)
if [[ $smbpcapcheck -eq 0 ]]; then
	rm smb.pcap
	printf '\nNo SMB traffic found. Deleting arbitrary smb.pcap.\n'
fi

#prompt for user input on extracting smb objects
printf '\nWould you like to export SMB objects? The objects will be outputted to a tarball in the current directory titled: smbObjects.tar.gz\n' 
printf '\n<<Warning>> There could be a lot of SMB objects and you can potentially extract malicious SMB objects depending on the pcap. Use with caution!!\n'

printf '(Please supply Y for yes or N for no)\n'

#prompt for user input
read smbAnswer


#if statement to check if yes, then pull objects
if [ $smbAnswer == 'Y' ] || [ $smbAnswer == 'y' ]
then
	tshark -nr $pcap -q --export-objects smb,./smbObjects 2>>errors.txt
	tar -czf smbObjects.tar.gz ./smbObjects
	rm -rf ./smbObjects

#SmbObject Check
	smbobjectcheck=$(tar -xzvf smbObjects.tar.gz | wc -l)
	if [[ $smbobjectcheck -eq 1 ]]; then
		rm smbObjects.tar.gz
		rm -rf ./smbObjects
		printf '\nNo SMB Objects found. Deleting arbitrary smbObjects.tar.gz.\n'
	else
#VirusTotal Integration
		printf '\nWould you like to lookup exported SMB objects using VirusTotal?\n**Warning** You must have ran the VTinitial.sh script to initialize PacketSifter with your VirusTotal API Key.\n'
		printf '(Please supply Y for yes or N for no)\n'
		read VTSMBLookup
			if [ $VTSMBLookup == 'Y' ] | [ $VTSMBLookup == 'y' ]
			then
				tar -xzf smbObjects.tar.gz
				for OBJ in $(ls ./smbObjects)
				do
					md5sum ./smbObjects/$OBJ >> ./smbHashToObject.txt
					cat smbHashToObject.txt | awk '{ print $1 }' | sort | uniq > lookupsmb.txt
				done

				while read THE
				do
					curl -s --request GET   --url https://www.virustotal.com/api/v3/files/$THE  --header 'x-apikey: data' | jq '.data.attributes.md5, .data.attributes.last_analysis_stats, .error' | grep -E code\|[a-f0-9]{32}\|malicious\|undetected >> output.txt
				done < lookupsmb.txt
				sed '/undetected/a\'$'\n'  output.txt > output2.txt 
				sed '/message/a\'$'\n' output2.txt > smbVTResults.txt
				rm -rf ./smbObjects
				rm lookupsmb.txt
				rm output.txt
				rm output2.txt
			fi
	fi
	rm -rf ./smbObjects
fi



#DNS sifting time
printf '\n\n\n################# DNS SIFTING #################\n\n'

#DNS packet carving
tshark -nr $pcap -Y 'dns' -w dns.pcap 2>>errors.txt
printf '\ndns.pcap contains all conversations categorized by tshark dissectors as DNS\n'

#DNS Pcap check
dnspcapcheck=$(tshark -r dns.pcap | wc -l)
if [[ $dnspcapcheck -eq 0 ]]; then
	rm dns.pcap
	printf 'No DNS traffic found. Deleting arbitrary dns.pcap\n'
fi

#DNS A record
tshark -nr $pcap -Y 'dns.qry.type == 1' -E header=y -T fields -e frame.number -e ip.src -e ip.dst -e dns.qry.name -e dns.a  > dnsARecords.txt 2>>errors.txt
printf '\nDNS A query/responses have been outputted to dnsARecords.txt\n'

#DNS A record check
dnsacheck=$(cat dnsARecords.txt | wc -l)
if [[ $dnsacheck -eq 1 ]]; then
	rm dnsARecords.txt
	printf 'No DNS A records found. Deleting arbitrary dnsARecords.txt\n'
fi

#AbuseIPDB lookup for A Records

printf '\nWould you like to lookup IP reputation/geolocation for DNS A record responses using AbuseIPDB?\n**Warning** You must have ran the AbuseIPDBInitial.sh script to initialize PacketSifter with your AbuseIPDB API Key.\n'
		printf '(Please supply Y for yes or N for no)\n'
		read AbuseLookup
		if [ $AbuseLookup == 'Y' ] | [ $AbuseLookup == 'y' ]
			then
				tshark -nr $pcap -T fields -e dns.a | tr ',' '\n' | sort | uniq > dstip.txt
				sed -i '1d' dstip.txt
			while read ABU
			do
				curl -s -G https://api.abuseipdb.com/api/v2/check   --data-urlencode "ipAddress=$ABU"   -d maxAgeInDays=90   -d verbose   -H "Key: Test"   -H "Accept: application/json" | jq '. | {IPaddress: .data.ipAddress, Domain: .data.domain, AbuseConfidenceScore: .data.abuseConfidenceScore, CountryCode: .data.countryCode, CountryName: .data.countryName}' >> output.txt
			done < dstip.txt
			sed '/}/a\'$'\n' output.txt > IPLookupResults.txt
			rm output.txt
			rm dstip.txt
		fi


#DNS TXT records
tshark -nr $pcap -Y 'dns.qry.type == 16' -E header=y -T fields -e frame.number -e ip.src -e ip.dst -e dns.resp.name -e dns.txt > dnsTXTRecords.txt 2>>errors.txt
printf '\nDNS TXT query/responses have been outputted to dnsTXTRecords.txt. DNS TXT records can be used for nefarious reasons and should be glanced over for any abnormalities.\n'

#DNS TXT record check
dnstxtcheck=$(cat dnsTXTRecords.txt | wc -l)
if [[ $dnstxtcheck -eq 1 ]]; then
	rm dnsTXTRecords.txt
	printf 'No DNS TXT records found. Deleting arbitrary dnsTXTRecords.txt\n'
fi 




#FTP sifting time
printf '\n\n\n################# FTP SIFTING #################\n'

#FTP packet carving
tshark -nr $pcap -Y 'ftp' -w ftp.pcap 2>>errors.txt
printf 'ftp.pcap contains all conversations categorized by tshark dissectors as FTP\n'

#FTP pcap check
ftpcheck=$(tshark -r ftp.pcap | wc -l)
if [[ $ftpcheck -eq 0 ]]; then
	rm ftp.pcap
	printf 'No FTP traffic found. Deleting arbitrary ftp.pcap\n'
fi



#errors.txt removal
errorcheck=$(cat errors.txt | wc -l)
if [[ $errorcheck -eq 0 ]]; then
	rm errors.txt
fi



#sifting done
printf '\nPacket sifting complete! Thanks for using the tool.\n'
printf '\nHappy hunting!\n'


