# PacketSifter

PacketSifter is a tool/script that is designed to aid analysts in sifting through a packet capture (pcap) to find noteworthy traffic. Packetsifter accepts a pcap as an argument and outputs several files.<br>
PackerSifter does NOT perform analysis for you. It simply sifts through data and puts specific pieces of data in buckets for ease of analysis. PacketSifter can be used to find IOCs present in a pcap however, you must still be able to interpret the data and drill down into the pcap to find points of interest.

<b>01/08/2021</b><br>
PacketSifter has received a major update to support VirusTotal lookups of objects exported by PacketSifter.

<b>12/31/2020</b><br>
Updated to delete associated txt/pcap files that contain 0 results, i.e., when 0 SMB results are found in pcap, all associated SMB output files produced by PacketSifter will be automatically deleted.


# Author
    Ross Burke (Twitter @packetsifter)


# How it works
Simply pass PacketSifter your pcap to analyze and answer Y or N when prompted and you're done!

<h5>Example:</h5> 

  root@ubuntu:~# ./packetsifter /tmp/testing.pcap

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
Currently, PacketSifter generates the following tar.gz files:
<ul>
<li>httpObjects.tar.gz (optional) - HTTP objects observed in pcap. <<Warning>> There could be a lot of HTTP objects and you can potentially extract malicious http objects depending on the pcap. Use with caution!! </li>
<li>smbObjects.tar.gz (optional) - SMB objects observed in pcap. There could be a lot of SMB objects and you can potentially extract malicious SMB objects depending on the pcap. Use with caution!! </li>
</ul>

# VirusTotal Integration
PacketSifter can now perform hash lookups via VirusTotal API of exported objects found via SMB/HTTP.<br>
<br>
<b>Steps to configure PacketSifter with VirusTotal integration:</b><br>
<br>

1. Ensure you have jq (https://stedolan.github.io/jq/download/)installed. <br>

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
5. Run PacketSifter and export either HTTP and/or SMB objects. Answer Y to performing lookups via VirusTotal when prompted. <br>
<br>
<b>Successful output of VirusTotal integration and subsequent generated httpVTResults.txt / smbVTResults.txt shown below: </b>
<img src=https://github.com/packetsifter/packetsifterTool/blob/main/screenshots/VTOutput.png></img>
        



# Suggestions?
Reach out if you have suggestions as to what else you'd like sifted or what else could be useful for the tool.
