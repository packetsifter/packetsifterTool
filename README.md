# PacketSifter
<p align="center">
<img src=https://github.com/packetsifter/packetsifterTool/blob/main/screenshots/logo-nobackground-500.png></img>
</p>

# What is PacketSifter?
PacketSifter is a tool to perform batch processing of PCAP data to uncover potential IOCs.<br>
Simply initializePacketSifter with your desired integrations (VirusTotal, AbuseIPDB) and pass PacketSifter a pcap and the desired switches and PacketSifter will sift through the data and generate several output files. <br>
<br>
**Note** Please run AbuseIPDBInitial.sh and VTInitial.sh prior to using their corresponding switches or the integrations will not work

<br><b>05/27/2021</b></br>
PacketSifter has been revamped to allow a more streamlined interaction with the user. Simply download the new updated packetsifter.sh, run ./packetsifter -h and learn how to properly use the new PacketSifter!




# Author
    Ross Burke (Twitter @packetsifter)


# How it works
Simply pass PacketSifter your pcap to analyze along with your desired flags and let PacketSifter do the work for you!

<h5>Example:</h5> 

  root@ubuntu:~# ./packetsifter -i /tmp/testing.pcap -a -r -v
  
# Command Line Options
OPTIONS:
    <ul>
    <li> -a      &emsp;  enable abuseipdb lookups of IP addresses in DNS A records </li>
    <li> -h      &emsp;  print help </li>
    <li> -i      &emsp;  input file [Required] </li>
    <li> -r      &emsp;  resolve hostnames in pcap [Can result in DNS queries to attacker infrastructure] </li>
    <li> -v      &emsp;  enable VirusTotal lookup of exported SMB/HTTP objects </li>
    </ul>

# Requirements
  tshark - https://tshark.dev/setup/install/
# Output 
Currently, PacketSifter generates the following pcaps:<br>
   <ul>
  <li>http.pcap - All conversations containing port 80, 8080, or 8000</li>
  <li>smb.pcap - All conversations categorized by tshark dissectors as NBSS, SMB, or SMB2 </li>
  <li>dns.pcap - All conversations categorized by tshark dissectors as DNS</li>
  <li>ftp.pcap - All conversations categorized by tshark dissectors as FTP</li>
</ul> 
<br>
Currently, PacketSifter generates the following text files:
   <ul>
  <li>IOstatistics.txt - Protocol Hierarchy and Input/Output broken up in 30 second intervals (useful to find potential beaconing)</li>
  <li>IPstatistics.txt - Overall stats to/from endpoints over IP and individual conversations over IP </li>
  <li>TCPstatistics - Overall stats to/from endpoints over TCP and individual TCP conversations broken down. <<Warning>> This file can contain a large amount of information. It is recommended to use less or grep for a conversation in question.</li>
  <li>http_info.txt - Statistical data about HTTP conversations</li>
  <li>hostnamesResolved.txt (optional) - Resolved hostnames observed in pcap. <<Warning>> This can result in DNS queries for attacker infrastructure. Proceed with caution!!
  <li>SMBstatistics.txt - Stats on commands ran using smb or smb2 </li>
  <li>dnsARecords.txt - DNS A query/responses </li>
  <li>dnsTXTRecords.txt - DNS TXT query/responses </li>
  <li>errors.txt - trash file </li> 
</ul>
<br>
VirusTotal Integration output text files (all optional):
    <ul>
        <li>httpHashToObject.txt - Text file containing md5 hash to object pairing for reference </li>
        <li>httpVTResults.txt - Text file containing results of md5 hash lookup of http objects via VirusTotal API </li>
        <li>smbHashToObject.txt - Text file containing md5 hash to object pairing for reference </li>
        <li>smbVTResults.txt - Text file containing results of md5 hash lookup of smb objects via VirusTotal API </li>
    </ul><br>
AbuseIPDB Integration output text files (optional):
    <ul>
        <li>IPLookupResults.txt - Text file containing IP Geo-location + IP reputation results</li>
    </ul><br>
Currently, PacketSifter generates the following tar.gz files:
<ul>
<li>httpObjects.tar.gz - HTTP objects observed in pcap. <<Warning>> There could be a lot of HTTP objects and you can potentially extract malicious http objects depending on the pcap. Use with caution!! </li>
<li>smbObjects.tar.gz - SMB objects observed in pcap. There could be a lot of SMB objects and you can potentially extract malicious SMB objects depending on the pcap. Use with caution!! </li>
</ul>

# VirusTotal Integration
PacketSifter can now perform hash lookups via VirusTotal API of exported objects found via SMB/HTTP.<br>
<br>
<b>Steps to configure PacketSifter with VirusTotal integration:</b><br>
<br>

1. Ensure you have jq (https://stedolan.github.io/jq/download/)  installed. <br>

        root@ubuntu:~# apt-get install jq
        
2. Ensure you have curl installed. <br>

         root@ubuntu:~# apt-get install curl
<br>
3. Download the new version of packetsifter.sh and the new script VTInitial.sh <br>
  4. Run VTInitial.sh in the same folder as packetsifter.sh and supply your 64 character alphanumeric VirusTotal API Key when prompted <br>
        &emsp;For instructions on how to obtain a free VirusTotal API Key https://developers.virustotal.com/reference <br>
<br>
<b> Successful output of VTInitial.sh is shown below: </b>
<img src=https://github.com/packetsifter/packetsifterTool/blob/main/screenshots/VTSuccess.png></img>
<br>
5. Run PacketSifter with the -v flag to enable VirusTotal lookups of exported HTTP and SMB objects. <br>
<br>
<b>Successful output of VirusTotal integration and subsequent generated httpVTResults.txt / smbVTResults.txt shown below: </b>
<img src=https://github.com/packetsifter/packetsifterTool/blob/main/screenshots/VTOutput.png></img>


# AbuseIPDB Integration
PacketSifter can perform IP Geo-location + IP reputation lookups of IP addresses returned in DNS A Records. <br>
<br>
<b>Steps to configure PacketSifter with AbuseIPDB integration:</b><br>
<br>

1. Ensure you have jq (https://stedolan.github.io/jq/download/)  installed. <br>

        root@ubuntu:~# apt-get install jq
        
2. Ensure you have curl installed. <br>

         root@ubuntu:~# apt-get install curl
<br>
3. Download the new version of packetsifter.sh and the new script AbuseIPDBInitial.sh <br>
  4. Run AbuseIPDBInitial.sh in the same folder as packetsifter.sh and supply your 80 character alphanumeric AbuseIPDB API Key when prompted. <br>        &emsp;For instructions on how to obtain a free AbuseIPDB API Key https://www.abuseipdb.com/register <br>
<br>
**AbuseIPDB free API keys have a limit of 1000 lookups a day** <br>
<b> Successful output of AbuseIPDBInitial.sh is shown below: </b>
<img src=https://github.com/packetsifter/packetsifterTool/blob/main/screenshots/AbuseIPDBInitialSuccess.png></img>
<br>
5. Run PacketSifter with the -a flag to enable lookups on DNS A records via AbuseIPDB. <br>
<br>
<b>Successful output of AbuseIPDB integration and subsequent generated IPLookupResults.txt shown below: </b>
<br>
**Confidence Score is on a 0-100 percent confidence scale**
<br>
<img src=https://github.com/packetsifter/packetsifterTool/blob/main/screenshots/IPLookupResults.png></img>



# Suggestions?
Reach out if you have suggestions as to what else you'd like sifted or what else could be useful for the tool.
