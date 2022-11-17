# RepScanner Utility
Reputation scan tool, automated reputation scan for hashes/URLs/Domains/IPs. This tool is built to help blue teamers while invetigating large amount of IOCs. It takes any IOC and report back to the user all relevant details an analyst will need in order to determine weather a file is malicious or legitimate.
# dependencies
### You need to install the following libraries in order to use RepScanner utility.
* [Install vt-py](https://github.com/VirusTotal/vt-py)
*  [Install OTXv2](https://github.com/AlienVault-OTX/OTX-Python-SDK) 
*  [Install whois](https://pypi.org/project/python-whois/)
*  [Install shodan](https://shodan.readthedocs.io/en/latest/)
*  [Install coloroma](https://pypi.org/project/colorama/)
*  [Install vxapi.py](https://github.com/PayloadSecurity/VxAPI)

# Usage
Search for the following columns within RepScanner source code and change them.
### Setting the API keys:
* 'api_key_vt': Changed this to your VT API key
* 'api_key_otx': Changed this to your OTX API key
* 'api_key_urlscan': Changed this to your URLSCAN API key
* 'api_key_abuseipdb': Changed this to your ABUSEIPDB API key
* 'api_key_shodan': Changed this to your SHODAN API key
### Setting the Vxapi.py path for execution:
* 'hybrid_analysis_path': Changed this to the path VxAPI.py is installed on your host
# Options
### Short help menu
* Type: python main.py -h for help
* Type: python main.py -H <Hash> for hash list scan
* Type: python main.py -i <IP> for IP address list scan
* Type: python main.py -d <Domain> for Doamin list scan
* Type: python main.py -u <URL> for URL list scan
