#!/usr/bin/env bash
printf '\nThis script will initialize your PacketSifter instance with your supplied VirusTotal API Key.\nYou will need to have curl (to make web requests) and jq (to format API output) installed on your machine for the VirusTotal integration to work.\nIf you do not have curl or jq installed, please do so before running this script and using the VirusTotal integration with PacketSifter.\n'

printf '\nPlease run this script in the same folder with packetsifter.sh or your API key will not be applied to the tool!!\n'
 
printf '\nPlease supply your VirusTotal API Key.\n(Your key should be a 64 character alphanumeric string)\n'

read vtAPIKey


sed -i -E s/'x\-apikey\:\s\w+'/'x\-apikey\:'\ $vtAPIKey/g ./packetsifter.sh 

curl --request GET --url https://www.virustotal.com/api/v3/urls/cf4b367e49bf0b22041c6f065f4aa19f3cfe39c8d5abc0617343d1a66c6a26f5 --header "x-apikey: $vtAPIKey" | jq .data.attributes.url

printf '\nIf you received the curl output of just the string "http://google.com/" then you should be good to go!\nIf you received output of null, then you may need to troubleshoot what failed. (Check your internet connection, invalid API Key, missing curl/jq, etc.)'
printf '\nSo long as you did not supply any whitespace character when inputting your API key when running this script initially, you can re-run this script again and resupply your API key and verify the VirusTotal integration with PacketSifter.\n' 
