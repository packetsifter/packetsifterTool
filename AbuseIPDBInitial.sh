#!/usr/bin/env bash
printf '\nThis script will initialize your PacketSifter instance with your supplied AbuseIPDB API Key.\nYou will need to have curl (to make web requests) and jq (to format API output) installed on your machine for the AbuseIPDB integration to work.\nIf you do not have curl or jq installed, please do so before running this script and using the AbuseIPDB integration with PacketSifter.\n'

printf '\nPlease run this script in the same folder with packetsifter.sh or your API key will not be applied to the tool!!\n'

printf '\nPlease supply your AbuseIPDB API Key.\n(Your key should be a 80 character alphanumeric string)\n'

read abuseKey


sed -i -E s/'Key\:\s\w+'/'Key\:'\ $abuseKey/g ./packetsifter.sh

curl -s -G https://api.abuseipdb.com/api/v2/check   --data-urlencode "ipAddress=8.8.8.8"   -d maxAgeInDays=90   -d verbose   -H "Key: $abuseKey"   -H "Accept: application/json" | jq '.data.domain'

printf '\nIf you received the curl output of just the string "google.com" then you should be good to go!\nIf you received output of null, then you may need to troubleshoot what failed. (Check your internet connection, invalid API Key, missing curl/jq, etc.)'
printf '\nSo long as you did not supply any whitespace character when inputting your API key when running this script initially, you can re-run this script again and resupply your API key and verify the AbuseIPDB integration with PacketSifter.\n'
