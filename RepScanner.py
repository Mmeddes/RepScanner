import vt  # VirusTotal library
import requests  # HTTP Requests library
from OTXv2 import OTXv2  # OTX library
from OTXv2 import IndicatorTypes
import json  # Json library
import colorama  # Colors library
from colorama import Fore
import os  # Interact with the OS
import subprocess  # Run external processes
import argparse  # Arguments library
import base64  # Base64 - encoding library
import whois  # WHOIS library
import shodan  # SHODAN library

# Making a parser and a description to the tool within the menu
parser = argparse.ArgumentParser(description=f'''{Fore.BLUE}repScanner utility, {Fore.WHITE}Blue team tool for better workflow with IOCs''')

# Adding a argument, -H or --hash-list for a hash list scan and adding the hashes to a list
parser.add_argument(
    '-H',
    '--hash-list',
    nargs='+',
    default=[],
    help=f'{Fore.BLUE}Enter your MD5/SHA1/SHA256 hashes with spaces.'
         f'{Fore.WHITE} Example: {Fore.BLUE}python main.py -H 8743b52063cd84097a65d1633f5c74f5{Fore.WHITE}')

# Adding argument, -d or --domain-list for a Domain list scan and adding the Domains to the list
parser.add_argument(
    '-d',
    '--domain-list',
    nargs='+',
    default=[],
    type=str,
    help=f'{Fore.BLUE}Enter your Domain list with spaces. '
         f'{Fore.WHITE}Example: {Fore.BLUE}python main.py -d example.com Some-domain.com{Fore.WHITE}')

# Adding argument, -u or --url-list for a URL list scan and adding the URLs to the list
parser.add_argument(
    '-u',
    '--url-list',
    nargs='+',
    default=[],
    type=str,
    help=f'{Fore.BLUE}Enter your URL list with spaces. '
         f'{Fore.WHITE}Example: {Fore.BLUE}python main.py -u hxxps[:]//example[.]com/ hxxps[:]//Some-domain[.]com/{Fore.WHITE}')

# Adding argument, -i or --ip-list for IP addresses list scan and adding the IPs to the list
parser.add_argument(
    '-i',
    '--ip-list',
    nargs='+',
    default=[],
    type=str,
    help=f'{Fore.BLUE}Enter you IP addresses list with spaces. '
         f'{Fore.WHITE}Example: {Fore.BLUE}python main.py -i 123.123.123.123 234.234.234.234{Fore.WHITE}')

# Making a mutually exclusive group to define -v/--verbose option.
group = parser.add_mutually_exclusive_group()

# Adding argument, -v or --verbose to get more details about the IOCs from the program
group.add_argument(
    '-v',
    '--verbose',
    action='store_true',
    help=f'{Fore.WHITE}Enter -v/--verbose to get the full details on your IOCs')

# Parsing the arguments
args = parser.parse_args()

# Defining the hash list
hash_list = args.hash_list

# Defining the Domain list
domain_list = args.domain_list

# Defining the URL list
url_list = args.url_list

# Defining the IP list
ip_list = args.ip_list

# Setting the color len to eq the letters
colorama.init(autoreset=True)

# Setting the API keys
api_key_vt = ""  ### Changed this
api_key_otx = ''  ### Changed this
api_key_urlscan = ''  ### Changed this
api_key_abuseipdb = ''  ### Changed this
api_key_shodan = ''  ### Changed this


# This is the parent function for all the *HASH* reputation scanners used in this script
def hash_reputation():
    ''' This is the parent function for all the *HASH* reputation scanners used in this script '''

    # This is a function to get a suspicious file hash results out of virus total API
    def virus_total():
        """ This is a function to get a suspicious file hash results out of virus total API """

        # Setting the base URL to send an HTTPS request
        base_url = "https://www.virustotal.com/api/v3/files/"

        # Setting the URL and the hash from the list together
        url = base_url + hash

        # Setting the headers with the API key inside
        headers = {
            "accept": "application/json",
            "x-apikey": api_key_vt
        }

        # Getting the response from the URL
        response = requests.get(url, headers=headers)

        # Getting the status code
        status_code = response.status_code

        # If statement to continue to the next iteration in the hash list when the response is 400 or higher
        if status_code >= 400:
            print(f"{Fore.WHITE}\n--- Start of VT analysis ---")
            print(f"{Fore.MAGENTA}No analysis available from VT about: {Fore.CYAN}{hash}")
            print(f"{Fore.WHITE}--- End of VT analysis ---\n")
        else:
            # Setting the client and the request to the url
            client = vt.Client(api_key_vt)
            file = ("/files/")
            url = client.get_object(file + hash)

            # Getting the analysis reports from the url
            analysis_report = url.last_analysis_stats
            analysis_report_json = client.get_json(file + hash)
            ###print(json.dumps(analysis_report_json, indent=6))

            # Getting results from the vendors
            mal = analysis_report["malicious"]
            undetected = analysis_report["undetected"]

            # Getting the sample sha1/sha256/md5
            sha1 = url.sha1
            sha256 = url.sha256
            md5 = url.md5

            # Getting other important file attributes
            file_size = url.size
            file_names = url.names[:5]
            times_Submitted = url.times_submitted
            type_Description = url.type_description

            # Setting a var to be the root json object of the vendors results, In order to get results from specific vendors
            data = analysis_report_json["data"]
            Attributes = data["attributes"]
            last_Analysis_results = Attributes["last_analysis_results"]

            # Extracting some columns that not always appear in the json file (Specific vendors, import list, and yara rules.)

            # Getting CS results
            if "CrowdStrike" in last_Analysis_results:
                vendor_two = last_Analysis_results["CrowdStrike"]['category']
                result_vendor_two = last_Analysis_results['CrowdStrike']['result']
            else:
                pass

            # Getting S1 results
            if "SentinelOne" in last_Analysis_results:
                vendor_one = last_Analysis_results["SentinelOne"]['category']
                result_vendor_one = last_Analysis_results['SentinelOne']['result']
            else:
                pass

            # Getting the import list (dll's) from VT
            if "pe_info" in Attributes:
                pe_info = Attributes["pe_info"]
                import_list = pe_info["import_list"]
            else:
                pass

            # Getting the crowd sourced YARA rules
            if "crowdsourced_yara_results" in Attributes:
                e = Attributes['crowdsourced_yara_results']
            else:
                pass

            if 'total_votes' in Attributes:
                total_votes_harmless = Attributes['total_votes']['harmless']
                total_votes_malicious = Attributes['total_votes']['malicious']

            else:
                pass

            if 'signature_info' in Attributes:
                signature_info = Attributes['signature_info']
            else:
                pass

            try:
                if 'product' in signature_info:
                    product = signature_info['product']
            except NameError:
                pass

            try:
                if 'internal name' in signature_info:
                    internal_name = signature_info['internal name']
            except NameError:
                pass

            try:
                if 'file version' in signature_info:
                    file_version = signature_info['file version']
            except NameError:
                pass

            try:
                if 'original name' in signature_info:
                    original_name = signature_info['original name']
            except NameError:
                pass

            try:
                if 'copyright' in signature_info:
                    copyright = signature_info['copyright']
            except NameError:
                pass

            try:
                if 'description' in signature_info:
                    description = signature_info['description']
            except NameError:
                pass

            # Printing the mandatory columns to the screen
            print(f"{Fore.WHITE}\n--- Start of VT analysis ---")
            print(f"{Fore.MAGENTA}Virus-Total results: https://www.virustotal.com/gui/file/{hash}")
            print(f"{Fore.WHITE}---")
            print(f"{Fore.LIGHTBLUE_EX}File Verdict: \n{Fore.RED}Malicious: {Fore.WHITE}{mal}")
            print(f"{Fore.GREEN}Undetected: {Fore.WHITE}{undetected}")
            print(f"{Fore.WHITE}---")
            print(f"{Fore.LIGHTBLUE_EX}File Hashes: \n{Fore.MAGENTA}SHA1: {Fore.WHITE}{sha1}")
            print(f"{Fore.MAGENTA}SHA256: {Fore.WHITE}{sha256}")
            print(f"{Fore.MAGENTA}MD5: {Fore.WHITE}{md5}")
            print(f"{Fore.WHITE}---")
            print(f"{Fore.LIGHTBLUE_EX}File Attributes: \n{Fore.MAGENTA}File type: {Fore.WHITE}{type_Description}")
            print(f"{Fore.MAGENTA}File size: {Fore.WHITE}{file_size}")
            print(f"{Fore.MAGENTA}Names: {Fore.WHITE}{file_names}")
            print(f"{Fore.MAGENTA}Times submitted: {Fore.WHITE}{times_Submitted}")

            # Printing the not mandatory columns to the screen (if they exist...)
            # Try printing the YARA rules
            if args.verbose:

                print(f"{Fore.WHITE}---")
                print(f"{Fore.LIGHTBLUE_EX}Detections:")

                try:
                    print(f"{Fore.MAGENTA}crowdsourced_yara_results: {Fore.WHITE}{e[0]}")
                except NameError:
                    print(f"{Fore.MAGENTA}crowdsourced_yara_results: {Fore.WHITE}N/A")

                # Try printing the S1 results
                try:
                    print(f"{Fore.MAGENTA}SentinelOne verdict: {Fore.WHITE}{vendor_one}, {Fore.MAGENTA}SentinelOne Result: {Fore.WHITE}{result_vendor_one}")
                except NameError:
                    print(f"{Fore.MAGENTA}SentinelOne verdict: {Fore.WHITE}N/A")

                # Try printing the CS results
                try:
                    print(f"{Fore.MAGENTA}CrowdStrike verdict: {Fore.WHITE}{vendor_two}, {Fore.MAGENTA}CrowdStrike Result: {Fore.WHITE}{result_vendor_two}")
                    print(f"{Fore.WHITE}---")

                except NameError:
                    print(f"{Fore.MAGENTA}CrowdStrike verdict: {Fore.WHITE}N/A")
                    print(f"{Fore.WHITE}---")

                # Try printing the import list (DLL's) VT found
                try:
                    for library in import_list[:50]:
                        library_name = library['library_name']
                        imported_functions = library['imported_functions']
                        print(f"{Fore.MAGENTA}Import name: {Fore.WHITE}{library_name}")
                        print(f'{Fore.MAGENTA}Imported functions ({library_name}): {Fore.WHITE}{imported_functions}')

                except NameError:
                    print(f"{Fore.MAGENTA}Imports: {Fore.WHITE}N/A")

            else:
                pass

            print(f"{Fore.WHITE}---")
            print(f'{Fore.BLUE}Total community votes:')

            # Try printing the total community votes
            try:
                print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}{total_votes_harmless}')
                print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}{total_votes_malicious}')
            except NameError:
                print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}N/A')
                print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}N/A')

            print(f"{Fore.WHITE}---")
            print(f'{Fore.BLUE}Signature info:')

            # Try printing the signature details
            try:
                print(f'{Fore.MAGENTA}Product: {Fore.WHITE}{product}')
            except NameError:
                print(f'{Fore.MAGENTA}Product: {Fore.WHITE}N/A')

            try:
                print(f'{Fore.MAGENTA}Internal name: {Fore.WHITE}{internal_name}')
            except NameError:
                print(f'{Fore.MAGENTA}Internal name: {Fore.WHITE}N/A')

            try:
                print(f'{Fore.MAGENTA}File version: {Fore.WHITE}{file_version}')
            except NameError:
                print(f'{Fore.MAGENTA}File version: {Fore.WHITE}N/A')

            try:
                print(f'{Fore.MAGENTA}Original name: {Fore.WHITE}{original_name}')
            except NameError:
                print(f'{Fore.MAGENTA}Original name: {Fore.WHITE}N/A')

            try:
                print(f'{Fore.MAGENTA}Copyright: {Fore.WHITE}{copyright}')
            except NameError:
                print(f'{Fore.MAGENTA}Copyright: {Fore.WHITE}N/A')

            try:
                print(f'{Fore.MAGENTA}Description: {Fore.WHITE}{description}')
            except NameError:
                print(f'{Fore.MAGENTA}Description: {Fore.WHITE}N/A')

            print(f"{Fore.WHITE}--- End of VT analysis ---\n")

    # This is a function to get all the relevant details about a hash via otx
    def otx():
        """ This is a function to get all the relevant details about a hash via otx """

        # The real OTX url for a ref
        otx_url_refer = 'https://otx.alienvault.com/indicator/file/'

        # Setting the request to otx
        otx = OTXv2(api_key_otx)
        results = otx.get_indicator_details_by_section(IndicatorTypes.FILE_HASH_SHA256, hash)
        results_full = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256, hash)

        # Getting the pulses number related to the hash/hashlist sample/s
        pulse_info = results["pulse_info"]
        count = pulse_info["count"]

        if count <= 0:

            # If the count of pulses is less or equal to 0 then display the below massage
            print(f"{Fore.WHITE}\n--- Start of OTX analysis ---")
            print(f"{Fore.MAGENTA}No pulses available from OTX about: {Fore.CYAN}{hash}")
        else:

            # If the count is anything else above 0 then do the following
            # Getting the pulses information
            pulses = pulse_info["pulses"]

            # Getting first pulse details
            pulse_one = pulses[0]
            id_one = pulse_one["id"]
            name_one = pulse_one["name"]
            created = pulse_one["created"]
            modified = pulse_one["modified"]
            tags = pulse_one["tags"]

            # Getting second pulse details
            pulse_two = pulses[1]
            id_two = pulse_two["id"]
            name_two = pulse_two["name"]
            created_two = pulse_two["created"]
            modified_two = pulse_two["modified"]
            tags_two = pulse_two["tags"]

            print(f"{Fore.WHITE}\n--- Start of OTX analysis ---")

            # Printing the pulses count
            print(f"{Fore.MAGENTA}OTX results: {Fore.CYAN}{otx_url_refer}{hash}")
            print(f"{Fore.WHITE}---")
            print(f"{Fore.MAGENTA}Pulses: {Fore.WHITE}{count}")
            print(f"{Fore.WHITE}---")

            # Printing the pulses results
            # First pulse
            print(f"{Fore.BLUE}First pulse: ")
            print(f"{Fore.MAGENTA}Pulse ID: {Fore.WHITE}{id_one}")
            print(f"{Fore.MAGENTA}Pulse name: {Fore.WHITE}{name_one}")
            print(f"{Fore.MAGENTA}Created: {Fore.WHITE}{created}")
            print(f"{Fore.MAGENTA}Modified: {Fore.WHITE}{modified}")
            print(f"{Fore.MAGENTA}Pulse tags: {Fore.WHITE}{tags}")
            print(f"{Fore.WHITE}---")

            # Second pulse
            print(f"{Fore.BLUE}Second pulse: ")
            print(f"{Fore.MAGENTA}Pulse ID: {Fore.WHITE}{id_two}")
            print(f"{Fore.MAGENTA}Pulse name: {Fore.WHITE}{name_two}")
            print(f"{Fore.MAGENTA}Created: {Fore.WHITE}{created_two}")
            print(f"{Fore.MAGENTA}Modified: {Fore.WHITE}{modified_two}")
            print(f"{Fore.MAGENTA}Pulse tags: {Fore.WHITE}{tags_two}")

        # Setting a var to "plugins" in order to parse specific vendors
        analysis = results_full["analysis"]
        analysis_x = analysis["analysis"]

        # Checking that "plugins" is in analysis results.
        if "plugins" in analysis_x:
            plugins = analysis_x["plugins"]
            print(f"{Fore.WHITE}---")
            print(f"{Fore.BLUE}Analysis details:")

            # Getting Avast verdict and printing it if exist
            if "avast" in plugins:
                avast = plugins["avast"]['results']
                if avast == {}:
                    print(f"{Fore.MAGENTA}Avast detection: {Fore.WHITE}N/A")
                else:
                    avast = avast['detection']
                    print(f"{Fore.MAGENTA}Avast detection: {Fore.WHITE}{avast}")

                # Getting ms-defender verdict and printing it if exist
                if "msdefender" in plugins:
                    msdefender = plugins["msdefender"]['results']
                    if msdefender == {}:
                        print(f"{Fore.MAGENTA}MSDefender detection: {Fore.WHITE}N/A")
                    else:
                        msdefender = msdefender['detection']
                        print(f"{Fore.MAGENTA}MSDefender detection: {Fore.WHITE}{msdefender}")

                        # Getting AVG verdict and printing it if exist
                        if "avg" in plugins:
                            avg = plugins["avg"]['results']['detection']
                            if avg == {}:
                                print(f"{Fore.MAGENTA}Exiftool: {Fore.WHITE}N/A")
                            else:
                                avg = avg['detection']
                                print(f"{Fore.MAGENTA}AVG detection: {Fore.WHITE}{avg}")
                                print(f"{Fore.WHITE}--- End of OTX analysis ---\n")

                        else:
                            print(f"{Fore.MAGENTA}AVG detection: {Fore.WHITE}N/A")
                else:
                    print(f"{Fore.MAGENTA}MSDefender detection: {Fore.WHITE}N/A")
            else:
                print(f"{Fore.MAGENTA}Avast detection: {Fore.WHITE}N/A")
        else:
            pass

        # Getting exiftool verdict and printing it if exist
        if args.verbose:

            try:
                if "exiftool" in plugins:
                    exiftool = plugins["exiftool"]['results']
                    if exiftool == {}:
                        print(f"{Fore.MAGENTA}Exiftool: {Fore.WHITE}N/A")

                    else:
                        print(f"{Fore.MAGENTA}Exiftool: {Fore.WHITE}{exiftool}")
            except NameError:
                pass
        else:
            pass

        print(f"{Fore.WHITE}--- End of OTX analysis ---\n")

    # This is a function to get all relevant details about a hash from HybridAnalysis
    def hybrid_analysis():
        """ This is a function to get all relevant details about a hash from HybridAnalysis """

        os.chdir('/Users/matansalamon/Downloads/VxAPI-master')
        p1 = subprocess.run(['python', 'vxapi.py', 'search_hash', hash], capture_output=True, text=True,)
        output = p1.stdout
        output_json = json.loads(output)

        # If output_json is empty then there is no analysis available, if else, analysis available
        if output_json == [] or output_json == {}:

            print(f"{Fore.WHITE}\n--- Start of Hybrid-Analysis analysis ---")
            print(f"{Fore.MAGENTA}No analysis available from HybridAnalysis for: {Fore.CYAN}{hash}")
            print(f"{Fore.WHITE}--- End of Hybrid-Analysis analysis ---\n")


        else:

            print(f"{Fore.WHITE}\n--- Start of Hybrid-Analysis analysis ---")

            analysis_start_time = output_json[0]['analysis_start_time']
            av_detect = output_json[0]['av_detect']
            environment_description = output_json[0]['environment_description']
            verdict = output_json[0]['verdict']
            malware_family = output_json[0]['vx_family']
            threat_level = output_json[0]['threat_level']
            threat_score = output_json[0]['threat_score']
            total_network_connections = output_json[0]['total_network_connections']
            total_processes = output_json[0]['total_processes']
            total_signatures = output_json[0]['total_signatures']
            type_file = output_json[0]['type']

            print(f'{Fore.BLUE}Metadata:')

            if analysis_start_time == None:
                print(f'{Fore.MAGENTA}Analysis date: {Fore.WHITE}N/A')
            else:
                print(f'{Fore.MAGENTA}Analysis date: {Fore.WHITE}{analysis_start_time}')

            if type_file == None:
                print(f'{Fore.MAGENTA}File type: {Fore.WHITE}N/A')
            else:
                print(f'{Fore.MAGENTA}File type: {Fore.WHITE}{type_file}')

            if environment_description == None:
                print(f'{Fore.MAGENTA}Environment description: {Fore.WHITE}N/A')
            else:
                print(f'{Fore.MAGENTA}Environment description: {Fore.WHITE}{environment_description}')

            print(f"{Fore.WHITE}---")

            print(f'{Fore.BLUE}Detections:')

            if av_detect == None:
                print(f'{Fore.MAGENTA}AV detections: {Fore.WHITE}N/A')
            else:
                print(f'{Fore.MAGENTA}AV detections: {Fore.WHITE}{av_detect}')

            if output_json[0]['classification_tags'] == []:
                print(f'{Fore.MAGENTA}Classification tags: {Fore.WHITE}N/A')
            else:
                classification_tags = output_json[0]['classification_tags']
                print(f'{Fore.MAGENTA}Classification tags: {Fore.WHITE}{classification_tags}')

            if output_json[0]['tags'] == []:
                print(f'{Fore.MAGENTA}More detection tags: {Fore.WHITE}N/A')
            else:
                tags = output_json[0]['tags']
                print(f'{Fore.MAGENTA}More detection tags: {Fore.WHITE}{tags}')

            print(f"{Fore.WHITE}---")
            print(f'{Fore.BLUE}File verdict:')

            if verdict == None:
                print(f'{Fore.MAGENTA}Verdict: {Fore.WHITE}N/A')
            else:
                print(f'{Fore.MAGENTA}Verdict: {Fore.WHITE}{verdict}')

            if malware_family == None:
                print(f'{Fore.MAGENTA}Malware family: {Fore.WHITE}N/A')
            else:
                print(f'{Fore.MAGENTA}Malware family: {Fore.WHITE}{malware_family}')

            if threat_level == None:
                print(f'{Fore.MAGENTA}Threat level: {Fore.WHITE}N/A')
            else:
                print(f'{Fore.MAGENTA}Threat level: {Fore.WHITE}{threat_level}')

            if threat_score == None:
                print(f'{Fore.MAGENTA}Threat score: {Fore.WHITE}N/A')
            else:
                print(f'{Fore.MAGENTA}Threat score: {Fore.WHITE}{threat_score}')

            print(f"{Fore.WHITE}---")

            print(f'{Fore.BLUE}File operations:')

            if total_network_connections == 0:
                print(f'{Fore.MAGENTA}Total network connections: {Fore.WHITE}No network connections found')
            else:
                print(f'{Fore.MAGENTA}Total network connections: {Fore.WHITE}{total_network_connections}')

            if total_processes == 0:
                print(f'{Fore.MAGENTA}Total processes: {Fore.WHITE}No processes found')
            else:
                print(f'{Fore.MAGENTA}Total processes: {Fore.WHITE}{total_processes}')

            if total_signatures == 0:
                print(f'{Fore.MAGENTA}Total signatures: {Fore.WHITE}No signatures found')
            else:
                print(f'{Fore.MAGENTA}Total signatures: {Fore.WHITE}{total_signatures}')

            print(f"{Fore.WHITE}--- End of Hybrid-Analysis analysis ---\n")

    # This is a for loop to iterate over to HASHES in the list provided by the user
    for hash in hash_list:
        print(f"{Fore.LIGHTGREEN_EX}[+]  {Fore.GREEN}START of Reputation scans for: {Fore.WHITE}{hash}  {Fore.LIGHTGREEN_EX}[+]")
        virus_total()
        otx()
        hybrid_analysis()
        print(f"{Fore.LIGHTRED_EX}[+]  {Fore.RED}END of reputation scans for: {Fore.WHITE}{hash}  {Fore.LIGHTRED_EX}[+]\n")


# This is the parent function for all the *DOMAIN* reputation scanners used in this script
def domain_reputation():
    ''' This is the parent function for all the *DOMAIN* reputation scanners used in this script '''

    # This is a function to get all relevant information about a Domain from VirusTotal
    def virus_total_domain():
        ''' This is a function to get all relevant information about a Domain from VirusTotal '''

        # Setting the base URL
        base_url = "https://www.virustotal.com/api/v3/urls/"

        # Setting the headers with the API key inside
        headers = {
            "accept": "application/json",
            "x-apikey": api_key_vt
        }

        response = requests.get(base_url + obj)

        # URL/Domain/IP list
        # url_list = ['1.161.101.20']

        # Getting the status code
        status_code = response.status_code

        if status_code == 400:
            print(f"{Fore.WHITE}\n--- Start of VT analysis ---")
            print(f"{Fore.MAGENTA}No analysis available from VT about: {Fore.CYAN}{obj}")
            print(f"{Fore.WHITE}--- End of VT analysis ---\n")

        else:
            print(f"{Fore.WHITE}\n--- Start of VT analysis ---")
            # Encoding the URL/Domain/IP provided with Base64 to get the "Identifier"
            url_id = base64.urlsafe_b64encode(obj.encode()).decode().strip("=")

            # Setting the base url with the Identifier
            url = base_url + url_id

            # Getting the response from VT
            response = requests.get(url, headers=headers)

            # Converting the response to python object
            response_json = json.loads(response.text)

            # If statement to break the operation if there is no analysis available
            if 'data' not in response_json:

                print(f'{Fore.MAGENTA}No analysis available from VT about: {Fore.CYAN}{obj}')
                print(f"{Fore.WHITE}--- End of VT analysis ---\n")

            # If there is an available analysis then do the following
            else:

                # Getting the last analysis stats back from VT if exist
                if 'last_analysis_stats' in response_json['data']['attributes']:
                    try:

                        harmless = response_json['data']['attributes']['last_analysis_stats']['harmless']
                        malicious = response_json['data']['attributes']['last_analysis_stats']['malicious']
                        suspicious = response_json['data']['attributes']['last_analysis_stats']['suspicious']
                        undetected = response_json['data']['attributes']['last_analysis_stats']['undetected']

                        # Printing the last analysis results if exist

                        print(f"{Fore.MAGENTA}Virus-Total results: {Fore.CYAN}{obj}")
                        print(f"{Fore.WHITE}---")

                        print(f'{Fore.BLUE}Last analysis stats:')
                        print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}{harmless}')
                        print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}{malicious}')
                        print(f'{Fore.MAGENTA}Suspicious: {Fore.WHITE}{suspicious}')
                        print(f'{Fore.MAGENTA}Undetected: {Fore.WHITE}{undetected}')
                        print(f"{Fore.WHITE}---")

                    except NameError:
                        pass
                else:
                    print(f"{Fore.WHITE}---")
                    print(f'{Fore.BLUE}Last analysis stats: {Fore.WHITE}N/A')
                    print(f"{Fore.WHITE}---")

                # Getting the total votes back from VT if exist
                if 'total_votes' in response_json['data']['attributes']:
                    try:
                        harmless = response_json['data']['attributes']['total_votes']['harmless']
                        malicious = response_json['data']['attributes']['total_votes']['malicious']

                        # Printing the results according to the results we got back from VT if exist
                        if harmless == 0 and malicious == 0:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}No votes yet')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}No votes yet')
                            print(f"{Fore.WHITE}---")

                        elif harmless == 0 and malicious > 0:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}No votes yet')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}{malicious}')
                            print(f"{Fore.WHITE}---")

                        elif malicious == 0 and harmless > 0:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}{harmless}')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}No votes yet')
                            print(f"{Fore.WHITE}---")

                        else:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}{harmless}')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}{malicious}')
                            print(f"{Fore.WHITE}---")

                    except NameError:
                        pass
                else:
                    print(f'{Fore.BLUE}Total votes: {Fore.WHITE}N/A')
                    print(f"{Fore.WHITE}---")

                print(f'{Fore.BLUE}Additional info:')

                # Getting the redirection chain from VT if exist
                if 'redirection_chain' in response_json['data']['attributes']:
                    try:
                        redirection_chain = response_json['data']['attributes']['redirection_chain']

                        # Printing the redirection chain if exist
                        print(f'{Fore.MAGENTA}Redirection chain: {Fore.WHITE}{redirection_chain}')
                    except NameError:
                        pass
                else:
                    print(f'{Fore.MAGENTA}Redirection chain: {Fore.WHITE}N/A ')

                # Getting the times submitted back from VT if exist
                if 'times_submitted' in response_json['data']['attributes']:
                    try:
                        times_submitted = response_json['data']['attributes']['times_submitted']

                        # Printing the times submitted results if exist
                        print(f'{Fore.MAGENTA}Times submitted: {Fore.WHITE}{times_submitted}')

                    except NameError:
                        pass
                else:
                    print(f'{Fore.MAGENTA}Times submitted: {Fore.WHITE}N/A')

                # Getting the vendors results
                # Kaspersky
                if args.verbose:
                    if 'last_analysis_results' in response_json['data']['attributes']:
                        try:
                            if 'Kaspersky' in response_json['data']['attributes']['last_analysis_results']:
                                kaspersky_category = \
                                response_json['data']['attributes']['last_analysis_results']['Kaspersky']['category']
                                kaspersky_method = \
                                response_json['data']['attributes']['last_analysis_results']['Kaspersky']['method']
                                kaspersky_result = \
                                response_json['data']['attributes']['last_analysis_results']['Kaspersky']['result']

                                print(f"{Fore.WHITE}---")
                                print(f'{Fore.BLUE}Last analysis results:')
                                print(f'{Fore.CYAN}Kaspersky results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{kaspersky_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{kaspersky_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{kaspersky_method}')
                                print(f"{Fore.WHITE}---")

                            else:
                                print(f'{Fore.CYAN}Kaspersky results: {Fore.WHITE}N/A')
                                print(f"{Fore.WHITE}---")


                        except NameError:
                            pass

                        # Avira
                        try:
                            if 'Avira' in response_json['data']['attributes']['last_analysis_results']:
                                avira_category = response_json['data']['attributes']['last_analysis_results']['Avira'][
                                    'category']
                                avira_method = response_json['data']['attributes']['last_analysis_results']['Avira'][
                                    'method']
                                avira_result = response_json['data']['attributes']['last_analysis_results']['Avira'][
                                    'result']

                                print(f'{Fore.CYAN}Avira results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{avira_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{avira_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{avira_method}')
                                print(f"{Fore.WHITE}---")

                            else:
                                print(f'{Fore.CYAN}Avira results: {Fore.WHITE}N/A')
                                print(f"{Fore.WHITE}---")

                        except NameError:
                            pass

                        # ESET
                        try:
                            if 'ESET' in response_json['data']['attributes']['last_analysis_results']:
                                eset_category = response_json['data']['attributes']['last_analysis_results']['ESET'][
                                    'category']
                                eset_method = response_json['data']['attributes']['last_analysis_results']['ESET'][
                                    'method']
                                eset_result = response_json['data']['attributes']['last_analysis_results']['ESET'][
                                    'result']

                                print(f'{Fore.CYAN}ESET results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{eset_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{eset_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{eset_method}')
                                print(f"{Fore.WHITE}---")

                            else:
                                print(f'{Fore.CYAN}ESET results: {Fore.WHITE}N/A')
                                print(f"{Fore.WHITE}---")

                        except NameError:
                            pass

                        # Google Safebrowsing
                        try:
                            if 'Google Safebrowsing' in response_json['data']['attributes']['last_analysis_results']:
                                google_category = \
                                    response_json['data']['attributes']['last_analysis_results']['Google Safebrowsing'][
                                        'category']
                                google_method = \
                                    response_json['data']['attributes']['last_analysis_results']['Google Safebrowsing'][
                                        'method']
                                google_result = \
                                    response_json['data']['attributes']['last_analysis_results']['Google Safebrowsing'][
                                        'result']

                                print(f'{Fore.CYAN}Google Safebrowsing results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{google_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{google_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{google_method}')

                            else:
                                print(f'{Fore.CYAN}Google Safebrowsing results: {Fore.WHITE}N/A')

                        except NameError:
                            pass

                    else:
                        print(f'Last analysis results: {Fore.WHITE}N/A')
                else:
                    pass

                print(f"{Fore.WHITE}--- End of VT analysis ---\n")

    # This is a function to get all the relevant details about a Domain via otx
    def otx_domain():
        """ This is a function to get all the relevant details about a Domain via otx """

        # Setting the request to otx
        otx = OTXv2(api_key_otx)

        results = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, obj)
        results_full = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, obj)

        # Getting the pulses number related to the hash/hashlist sample/s
        pulse_info = results["pulse_info"]
        count = pulse_info["count"]

        if count <= 0:

            # If the count of pulses is less or equal to 0 then display the below massage
            print(f"{Fore.WHITE}\n--- Start of OTX analysis ---")
            print(f"{Fore.MAGENTA}No pulses available from OTX about: {Fore.CYAN}{obj}")
            print(f"{Fore.WHITE}--- End of OTX analysis ---\n")

        else:

            pulses = pulse_info['pulses']

            # Getting first pulse details
            pulse_one = pulses[0]
            id_one = pulse_one["id"]
            name_one = pulse_one["name"]
            created = pulse_one["created"]
            modified = pulse_one["modified"]
            tags = pulse_one["tags"]

            # Getting second pulse details
            if count == 1:
                pass
            else:
                try:
                    pulse_two = pulses[1]
                    id_two = pulse_two["id"]
                    name_two = pulse_two["name"]
                    created_two = pulse_two["created"]
                    modified_two = pulse_two["modified"]
                    tags_two = pulse_two["tags"]
                except NameError:
                    pass

            if args.verbose:
                if count >= 3:
                    # Getting the third pulse details
                    try:
                        pulse_three = pulses[2]
                        id_three = pulse_three["id"]
                        name_three = pulse_three["name"]
                        created_three = pulse_three["created"]
                        modified_three = pulse_three["modified"]
                        tags_three = pulse_three["tags"]
                    except NameError:
                        pass
                else:
                    pass

                if count >= 4:
                    try:
                        pulse_forth = pulses[3]
                        id_forth = pulse_forth["id"]
                        name_forth = pulse_forth["name"]
                        created_forth = pulse_forth["created"]
                        modified_forth = pulse_forth["modified"]
                        tags_forth = pulse_forth["tags"]
                    except NameError:
                        pass
                else:
                    pass

            else:
                pass



            print(f"{Fore.WHITE}\n--- Start of OTX analysis ---")

            # Printing the pulses count
            print(f"{Fore.MAGENTA}OTX results: {Fore.CYAN}{obj}")
            print(f"{Fore.WHITE}---")
            print(f"{Fore.MAGENTA}Pulses: {Fore.WHITE}{count}")
            print(f"{Fore.WHITE}---")

            # Printing the pulses results
            # First pulse
            try:
                print(f"{Fore.BLUE}First pulse: ")
                print(f"{Fore.MAGENTA}Pulse ID: {Fore.WHITE}{id_one}")
                print(f"{Fore.MAGENTA}Pulse name: {Fore.WHITE}{name_one}")
                print(f"{Fore.MAGENTA}Created: {Fore.WHITE}{created}")
                print(f"{Fore.MAGENTA}Modified: {Fore.WHITE}{modified}")
                print(f"{Fore.MAGENTA}Pulse tags: {Fore.WHITE}{tags}")
            except NameError:
                pass

            # Second pulse
            if count == 1:
                pass
            else:
                try:
                    print(f"{Fore.WHITE}---")
                    print(f"{Fore.BLUE}Second pulse: ")
                    print(f"{Fore.MAGENTA}Pulse ID: {Fore.WHITE}{id_two}")
                    print(f"{Fore.MAGENTA}Pulse name: {Fore.WHITE}{name_two}")
                    print(f"{Fore.MAGENTA}Created: {Fore.WHITE}{created_two}")
                    print(f"{Fore.MAGENTA}Modified: {Fore.WHITE}{modified_two}")
                    print(f"{Fore.MAGENTA}Pulse tags: {Fore.WHITE}{tags_two}")
                except NameError:
                    pass

            if args.verbose:
                if count >= 3:
                    # Third pulse
                    try:
                        print(f"{Fore.BLUE}Third pulse: (--verbose)")
                        print(f"{Fore.MAGENTA}Pulse ID: {Fore.WHITE}{id_three}")
                        print(f"{Fore.MAGENTA}Pulse name: {Fore.WHITE}{name_three}")
                        print(f"{Fore.MAGENTA}Created: {Fore.WHITE}{created_three}")
                        print(f"{Fore.MAGENTA}Modified: {Fore.WHITE}{modified_three}")
                        print(f"{Fore.MAGENTA}Pulse tags: {Fore.WHITE}{tags_three}")
                    except NameError:
                        pass
                else:
                    pass

                if count >= 4:
                    # Forth pulse
                    try:
                        print(f"{Fore.BLUE}Forth pulse: (--verbose)")
                        print(f"{Fore.MAGENTA}Pulse ID: {Fore.WHITE}{id_forth}")
                        print(f"{Fore.MAGENTA}Pulse name: {Fore.WHITE}{name_forth}")
                        print(f"{Fore.MAGENTA}Created: {Fore.WHITE}{created_forth}")
                        print(f"{Fore.MAGENTA}Modified: {Fore.WHITE}{modified_forth}")
                        print(f"{Fore.MAGENTA}Pulse tags: {Fore.WHITE}{tags_forth}")
                    except NameError:
                        pass
                else:
                    pass

            else:
                pass

            print(f"{Fore.WHITE}--- End of OTX analysis ---\n")

    # This is a function to get all relevant information about a Domain via WHOIS
    def whois_domain():
        ''' This is a function to get all relevant information about a Domain via WHOIS '''

        try:
            w = whois.whois(obj)
            print(f"{Fore.WHITE}\n--- Start of WHOIS analysis ---")
            print(f'{Fore.BLUE}WHOIS analysis: {Fore.CYAN}{obj}')
            print(f"{Fore.WHITE}---")
            print(f'{Fore.MAGENTA}Domain name: {Fore.WHITE}{w.domain_name}')
            print(f'{Fore.MAGENTA}Registrar: {Fore.WHITE}{w.registrar}')
            print(f'{Fore.MAGENTA}Referral URL: {Fore.WHITE}{w.referral_url}')
            print(f'{Fore.MAGENTA}Updated date: {Fore.WHITE}{w.updated_date}')
            print(f'{Fore.MAGENTA}Creation date: {Fore.WHITE}{w.creation_date}')
            print(f'{Fore.MAGENTA}Expiration date: {Fore.WHITE}{w.expiration_date}')
            print(f'{Fore.MAGENTA}Name: {Fore.WHITE}{w.name}')
            print(f'{Fore.MAGENTA}org: {Fore.WHITE}{w.org}')
            print(f'{Fore.MAGENTA}country: {Fore.WHITE}{w.country}')
            print(f'{Fore.MAGENTA}state: {Fore.WHITE}{w.state}')
            print(f'{Fore.MAGENTA}city: {Fore.WHITE}{w.city}')
            print(f'{Fore.MAGENTA}address: {Fore.WHITE}{w.address}')
            print(f"{Fore.WHITE}--- End of WHOIS analysis ---\n")
        except:
            print(f"{Fore.WHITE}\n--- Start of WHOIS analysis ---")
            print(f'{Fore.MAGENTA}No WHOIS analysis available: {Fore.CYAN}{obj}')
            print(f"{Fore.WHITE}--- End of WHOIS analysis ---\n")

    # This is a for loop to iterate over to DOMAINS in the list provided by the user
    for obj in domain_list:
        print(f"{Fore.LIGHTGREEN_EX}[+]  {Fore.GREEN}START of Reputation scans for: {Fore.WHITE}{obj}  {Fore.LIGHTGREEN_EX}[+]")
        virus_total_domain()
        otx_domain()
        whois_domain()
        print(f"{Fore.LIGHTRED_EX}[+]  {Fore.RED}END of reputation scans for: {Fore.WHITE}{obj}  {Fore.LIGHTRED_EX}[+]\n")


# This is the parent function for all the *URL* reputation scanners used in this script
def url_reputation():
    ''' This is the parent function for all the *URL* reputation scanners used in this script '''

    # This is a function to get all relevant information about a URL from VirusTotal
    def virus_total_url():
        ''' This is a function to get all relevant information about a URL from VirusTotal '''

        # Setting the base URL
        base_url = "https://www.virustotal.com/api/v3/urls/"

        # Setting the headers with the API key inside
        headers = {
            "accept": "application/json",
            "x-apikey": api_key_vt
        }

        response = requests.get(base_url + obj)

        # URL/Domain/IP list
        # url_list = ['1.161.101.20']

        # Getting the status code
        status_code = response.status_code

        if status_code == 400:
            print(f"{Fore.WHITE}\n--- Start of VT analysis ---")
            print(f"{Fore.MAGENTA}No analysis available from VT about: {Fore.CYAN}{obj}")
            print(f"{Fore.WHITE}--- End of VT analysis ---\n")

        else:
            print(f"{Fore.WHITE}\n--- Start of VT analysis ---")
            # Encoding the URL/Domain/IP provided with Base64 to get the "Identifier"
            url_id = base64.urlsafe_b64encode(obj.encode()).decode().strip("=")

            # Setting the base url with the Identifier
            url = base_url + url_id

            # Getting the response from VT
            response = requests.get(url, headers=headers)

            # Converting the response to python object
            response_json = json.loads(response.text)

            # If statement to break the operation if there is no analysis available
            if 'data' not in response_json:

                print(f'{Fore.MAGENTA}No analysis available from VT about: {Fore.CYAN}{obj}')
                print(f"{Fore.WHITE}--- End of VT analysis ---\n")

            # If there is an available analysis then do the following
            else:

                # Getting the last analysis stats back from VT if exist
                if 'last_analysis_stats' in response_json['data']['attributes']:
                    try:

                        harmless = response_json['data']['attributes']['last_analysis_stats']['harmless']
                        malicious = response_json['data']['attributes']['last_analysis_stats']['malicious']
                        suspicious = response_json['data']['attributes']['last_analysis_stats']['suspicious']
                        undetected = response_json['data']['attributes']['last_analysis_stats']['undetected']

                        # Printing the last analysis results if exist

                        print(f"{Fore.MAGENTA}Virus-Total results: {Fore.CYAN}{obj}")
                        print(f"{Fore.WHITE}---")

                        print(f'{Fore.BLUE}Last analysis stats:')
                        print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}{harmless}')
                        print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}{malicious}')
                        print(f'{Fore.MAGENTA}Suspicious: {Fore.WHITE}{suspicious}')
                        print(f'{Fore.MAGENTA}Undetected: {Fore.WHITE}{undetected}')
                        print(f"{Fore.WHITE}---")

                    except NameError:
                        pass
                else:
                    print(f"{Fore.WHITE}---")
                    print(f'{Fore.BLUE}Last analysis stats: {Fore.WHITE}N/A')
                    print(f"{Fore.WHITE}---")

                # Getting the total votes back from VT if exist
                if 'total_votes' in response_json['data']['attributes']:
                    try:
                        harmless = response_json['data']['attributes']['total_votes']['harmless']
                        malicious = response_json['data']['attributes']['total_votes']['malicious']

                        # Printing the results according to the results we got back from VT if exist
                        if harmless == 0 and malicious == 0:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}No votes yet')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}No votes yet')
                            print(f"{Fore.WHITE}---")

                        elif harmless == 0 and malicious > 0:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}No votes yet')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}{malicious}')
                            print(f"{Fore.WHITE}---")

                        elif malicious == 0 and harmless > 0:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}{harmless}')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}No votes yet')
                            print(f"{Fore.WHITE}---")

                        else:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}{harmless}')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}{malicious}')
                            print(f"{Fore.WHITE}---")

                    except NameError:
                        pass
                else:
                    print(f'{Fore.BLUE}Total votes: {Fore.WHITE}N/A')
                    print(f"{Fore.WHITE}---")

                print(f'{Fore.BLUE}Additional info:')

                # Getting the redirection chain from VT if exist
                if 'redirection_chain' in response_json['data']['attributes']:
                    try:
                        redirection_chain = response_json['data']['attributes']['redirection_chain']

                        # Printing the redirection chain if exist
                        print(f'{Fore.MAGENTA}Redirection chain: {Fore.WHITE}{redirection_chain}')
                    except NameError:
                        pass
                else:
                    print(f'{Fore.MAGENTA}Redirection chain: {Fore.WHITE}N/A ')

                # Getting the times submitted back from VT if exist
                if 'times_submitted' in response_json['data']['attributes']:
                    try:
                        times_submitted = response_json['data']['attributes']['times_submitted']

                        # Printing the times submitted results if exist
                        print(f'{Fore.MAGENTA}Times submitted: {Fore.WHITE}{times_submitted}')

                    except NameError:
                        pass
                else:
                    print(f'{Fore.MAGENTA}Times submitted: {Fore.WHITE}N/A')

                # Getting the vendors results
                # Kaspersky
                if args.verbose:
                    if 'last_analysis_results' in response_json['data']['attributes']:
                        try:
                            if 'Kaspersky' in response_json['data']['attributes']['last_analysis_results']:
                                kaspersky_category = \
                                    response_json['data']['attributes']['last_analysis_results']['Kaspersky'][
                                        'category']
                                kaspersky_method = \
                                    response_json['data']['attributes']['last_analysis_results']['Kaspersky']['method']
                                kaspersky_result = \
                                    response_json['data']['attributes']['last_analysis_results']['Kaspersky']['result']

                                print(f"{Fore.WHITE}---")
                                print(f'{Fore.BLUE}Last analysis results:')
                                print(f'{Fore.CYAN}Kaspersky results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{kaspersky_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{kaspersky_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{kaspersky_method}')
                                print(f"{Fore.WHITE}---")

                            else:
                                print(f'{Fore.CYAN}Kaspersky results: {Fore.WHITE}N/A')
                                print(f"{Fore.WHITE}---")


                        except NameError:
                            pass

                        # Avira
                        try:
                            if 'Avira' in response_json['data']['attributes']['last_analysis_results']:
                                avira_category = response_json['data']['attributes']['last_analysis_results']['Avira'][
                                    'category']
                                avira_method = response_json['data']['attributes']['last_analysis_results']['Avira'][
                                    'method']
                                avira_result = response_json['data']['attributes']['last_analysis_results']['Avira'][
                                    'result']

                                print(f'{Fore.CYAN}Avira results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{avira_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{avira_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{avira_method}')
                                print(f"{Fore.WHITE}---")

                            else:
                                print(f'{Fore.CYAN}Avira results: {Fore.WHITE}N/A')
                                print(f"{Fore.WHITE}---")

                        except NameError:
                            pass

                        # ESET
                        try:
                            if 'ESET' in response_json['data']['attributes']['last_analysis_results']:
                                eset_category = response_json['data']['attributes']['last_analysis_results']['ESET'][
                                    'category']
                                eset_method = response_json['data']['attributes']['last_analysis_results']['ESET'][
                                    'method']
                                eset_result = response_json['data']['attributes']['last_analysis_results']['ESET'][
                                    'result']

                                print(f'{Fore.CYAN}ESET results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{eset_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{eset_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{eset_method}')
                                print(f"{Fore.WHITE}---")

                            else:
                                print(f'{Fore.CYAN}ESET results: {Fore.WHITE}N/A')
                                print(f"{Fore.WHITE}---")

                        except NameError:
                            pass

                        # Google Safebrowsing
                        try:
                            if 'Google Safebrowsing' in response_json['data']['attributes']['last_analysis_results']:
                                google_category = \
                                    response_json['data']['attributes']['last_analysis_results']['Google Safebrowsing'][
                                        'category']
                                google_method = \
                                    response_json['data']['attributes']['last_analysis_results']['Google Safebrowsing'][
                                        'method']
                                google_result = \
                                    response_json['data']['attributes']['last_analysis_results']['Google Safebrowsing'][
                                        'result']

                                print(f'{Fore.CYAN}Google Safebrowsing results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{google_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{google_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{google_method}')

                            else:
                                print(f'{Fore.CYAN}Google Safebrowsing results: {Fore.WHITE}N/A')

                        except NameError:
                            pass

                    else:
                        print(f'Last analysis results: {Fore.WHITE}N/A')
                else:
                    pass

                print(f"{Fore.WHITE}--- End of VT analysis ---\n")

    # This is a function to get all relevant information about a URL from URLSCAN
    def urlscan():
        ''' This is a function to get all relevant information about a URL from URLSCAN '''

        headers = {'API-Key': api_key_urlscan, 'Content-Type': 'application/json'}
        data = {"url": obj, "visibility": "public"}
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))

        response_json = json.loads(response.text)

        if response_json['message'] == 'Submission successful':
            try:
                result = response_json['result']
                print(f"\n{Fore.WHITE}--- Start of URLScan analysis ---")
                print(f'{Fore.MAGENTA}Result: {result}')
                print(f"{Fore.WHITE}--- End of URLScan analysis ---\n")
            except NameError:
                pass
        else:
            print(f"\n{Fore.WHITE}--- Start of URLScan analysis ---")
            print(f'{Fore.MAGENTA}The submission was unsuccessful for: {obj}')
            print(f"{Fore.WHITE}--- End of URLScan analysis ---\n")

    # This is a function to get all relevant information about a URL via WHOIS
    def whois_url():
        ''' This is a function to get all relevant information about a URL via WHOIS '''

        try:
            w = whois.whois(obj)
            print(f"{Fore.WHITE}\n--- Start of WHOIS analysis ---")
            print(f'{Fore.BLUE}WHOIS analysis: {Fore.CYAN}{obj}')
            print(f"{Fore.WHITE}---")
            print(f'{Fore.MAGENTA}Domain name: {Fore.WHITE}{w.domain_name}')
            print(f'{Fore.MAGENTA}Registrar: {Fore.WHITE}{w.registrar}')
            print(f'{Fore.MAGENTA}Referral URL: {Fore.WHITE}{w.referral_url}')
            print(f'{Fore.MAGENTA}Updated date: {Fore.WHITE}{w.updated_date}')
            print(f'{Fore.MAGENTA}Creation date: {Fore.WHITE}{w.creation_date}')
            print(f'{Fore.MAGENTA}Expiration date: {Fore.WHITE}{w.expiration_date}')
            print(f'{Fore.MAGENTA}Name: {Fore.WHITE}{w.name}')
            print(f'{Fore.MAGENTA}org: {Fore.WHITE}{w.org}')
            print(f'{Fore.MAGENTA}country: {Fore.WHITE}{w.country}')
            print(f'{Fore.MAGENTA}state: {Fore.WHITE}{w.state}')
            print(f'{Fore.MAGENTA}city: {Fore.WHITE}{w.city}')
            print(f'{Fore.MAGENTA}address: {Fore.WHITE}{w.address}')
            print(f"{Fore.WHITE}--- End of WHOIS analysis ---\n")
        except:
            print(f"{Fore.WHITE}\n--- Start of WHOIS analysis ---")
            print(f'{Fore.MAGENTA}No WHOIS analysis available: {Fore.CYAN}{obj}')
            print(f"{Fore.WHITE}--- End of WHOIS analysis ---\n")

    # This is a for loop to iterate over to URLs in the list provided by the user
    for obj in url_list:
        print(f"{Fore.LIGHTGREEN_EX}[+]  {Fore.GREEN}START of Reputation scans for: {Fore.WHITE}{obj}  {Fore.LIGHTGREEN_EX}[+]")
        virus_total_url()
        urlscan()
        whois_url()
        print(f"{Fore.LIGHTRED_EX}[+]  {Fore.RED}END of reputation scans for: {Fore.WHITE}{obj}  {Fore.LIGHTRED_EX}[+]\n")


# This is the parent function for all the *IP addresses* reputation scanners used in this script
def ip_reputation():
    ''' This is the parent function for all the *IP addresses* reputation scanners used in this script '''

    # This is a function to get all relevant information about an IP address from VirusTotal
    def virustotal_ip():
        ''' This is a function to get all relevant information about an IP address from VirusTotal '''

        # Setting the base URL
        base_url = "https://www.virustotal.com/api/v3/urls/"

        # Setting the headers with the API key inside
        headers = {
            "accept": "application/json",
            "x-apikey": api_key_vt
        }

        response = requests.get(base_url + ip)

        # URL/Domain/IP list
        # url_list = ['1.161.101.20']

        # Getting the status code
        status_code = response.status_code

        if status_code == 400:
            print(f"{Fore.WHITE}\n--- Start of VT analysis ---")
            print(f"{Fore.MAGENTA}No analysis available from VT about: {Fore.CYAN}{ip}")
            print(f"{Fore.WHITE}--- End of VT analysis ---\n")

        else:
            print(f"{Fore.WHITE}\n--- Start of VT analysis ---")
            # Encoding the URL/Domain/IP provided with Base64 to get the "Identifier"
            url_id = base64.urlsafe_b64encode(ip.encode()).decode().strip("=")

            # Setting the base url with the Identifier
            url = base_url + url_id

            # Getting the response from VT
            response = requests.get(url, headers=headers)

            # Converting the response to python object
            response_json = json.loads(response.text)

            # If statement to break the operation if there is no analysis available
            if 'data' not in response_json:

                print(f'{Fore.MAGENTA}No analysis available from VT about: {Fore.CYAN}{ip}')
                print(f"{Fore.WHITE}--- End of VT analysis ---\n")

            # If there is an available analysis then do the following
            else:

                # Getting the last analysis stats back from VT if exist
                if 'last_analysis_stats' in response_json['data']['attributes']:
                    try:

                        harmless = response_json['data']['attributes']['last_analysis_stats']['harmless']
                        malicious = response_json['data']['attributes']['last_analysis_stats']['malicious']
                        suspicious = response_json['data']['attributes']['last_analysis_stats']['suspicious']
                        undetected = response_json['data']['attributes']['last_analysis_stats']['undetected']

                        # Printing the last analysis results if exist

                        print(f"{Fore.BLUE}Virus-Total analysis: {Fore.CYAN}{ip}")
                        print(f"{Fore.WHITE}---")

                        print(f'{Fore.BLUE}Last analysis stats:')
                        print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}{harmless}')
                        print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}{malicious}')
                        print(f'{Fore.MAGENTA}Suspicious: {Fore.WHITE}{suspicious}')
                        print(f'{Fore.MAGENTA}Undetected: {Fore.WHITE}{undetected}')
                        print(f"{Fore.WHITE}---")

                    except NameError:
                        pass
                else:
                    print(f"{Fore.WHITE}---")
                    print(f'{Fore.BLUE}Last analysis stats: {Fore.WHITE}N/A')
                    print(f"{Fore.WHITE}---")

                # Getting the total votes back from VT if exist
                if 'total_votes' in response_json['data']['attributes']:
                    try:
                        harmless = response_json['data']['attributes']['total_votes']['harmless']
                        malicious = response_json['data']['attributes']['total_votes']['malicious']

                        # Printing the results according to the results we got back from VT if exist
                        if harmless == 0 and malicious == 0:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}No votes yet')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}No votes yet')
                            print(f"{Fore.WHITE}---")

                        elif harmless == 0 and malicious > 0:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}No votes yet')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}{malicious}')
                            print(f"{Fore.WHITE}---")

                        elif malicious == 0 and harmless > 0:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}{harmless}')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}No votes yet')
                            print(f"{Fore.WHITE}---")

                        else:
                            print(f'{Fore.BLUE}Total votes:')
                            print(f'{Fore.MAGENTA}Harmless: {Fore.WHITE}{harmless}')
                            print(f'{Fore.MAGENTA}Malicious: {Fore.WHITE}{malicious}')
                            print(f"{Fore.WHITE}---")

                    except NameError:
                        pass
                else:
                    print(f'{Fore.BLUE}Total votes: {Fore.WHITE}N/A')
                    print(f"{Fore.WHITE}---")

                print(f'{Fore.BLUE}Additional info:')

                # Getting the redirection chain from VT if exist
                if 'redirection_chain' in response_json['data']['attributes']:
                    try:
                        redirection_chain = response_json['data']['attributes']['redirection_chain']

                        # Printing the redirection chain if exist
                        print(f'{Fore.MAGENTA}Redirection chain: {Fore.WHITE}{redirection_chain}')
                    except NameError:
                        pass
                else:
                    print(f'{Fore.MAGENTA}Redirection chain: {Fore.WHITE}N/A ')

                # Getting the times submitted back from VT if exist
                if 'times_submitted' in response_json['data']['attributes']:
                    try:
                        times_submitted = response_json['data']['attributes']['times_submitted']

                        # Printing the times submitted results if exist
                        print(f'{Fore.MAGENTA}Times submitted: {Fore.WHITE}{times_submitted}')

                    except NameError:
                        pass
                else:
                    print(f'{Fore.MAGENTA}Times submitted: {Fore.WHITE}N/A')

                # Getting the vendors results
                # Kaspersky
                if args.verbose:
                    if 'last_analysis_results' in response_json['data']['attributes']:
                        try:
                            if 'Kaspersky' in response_json['data']['attributes']['last_analysis_results']:
                                kaspersky_category = \
                                    response_json['data']['attributes']['last_analysis_results']['Kaspersky'][
                                        'category']
                                kaspersky_method = \
                                    response_json['data']['attributes']['last_analysis_results']['Kaspersky']['method']
                                kaspersky_result = \
                                    response_json['data']['attributes']['last_analysis_results']['Kaspersky']['result']

                                print(f"{Fore.WHITE}---")
                                print(f'{Fore.BLUE}Last analysis results:')
                                print(f'{Fore.CYAN}Kaspersky results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{kaspersky_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{kaspersky_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{kaspersky_method}')
                                print(f"{Fore.WHITE}---")

                            else:
                                print(f'{Fore.CYAN}Kaspersky results: {Fore.WHITE}N/A')
                                print(f"{Fore.WHITE}---")


                        except NameError:
                            pass

                        # Avira
                        try:
                            if 'Avira' in response_json['data']['attributes']['last_analysis_results']:
                                avira_category = response_json['data']['attributes']['last_analysis_results']['Avira'][
                                    'category']
                                avira_method = response_json['data']['attributes']['last_analysis_results']['Avira'][
                                    'method']
                                avira_result = response_json['data']['attributes']['last_analysis_results']['Avira'][
                                    'result']

                                print(f'{Fore.CYAN}Avira results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{avira_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{avira_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{avira_method}')
                                print(f"{Fore.WHITE}---")

                            else:
                                print(f'{Fore.CYAN}Avira results: {Fore.WHITE}N/A')
                                print(f"{Fore.WHITE}---")

                        except NameError:
                            pass

                        # ESET
                        try:
                            if 'ESET' in response_json['data']['attributes']['last_analysis_results']:
                                eset_category = response_json['data']['attributes']['last_analysis_results']['ESET'][
                                    'category']
                                eset_method = response_json['data']['attributes']['last_analysis_results']['ESET'][
                                    'method']
                                eset_result = response_json['data']['attributes']['last_analysis_results']['ESET'][
                                    'result']

                                print(f'{Fore.CYAN}ESET results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{eset_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{eset_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{eset_method}')
                                print(f"{Fore.WHITE}---")

                            else:
                                print(f'{Fore.CYAN}ESET results: {Fore.WHITE}N/A')
                                print(f"{Fore.WHITE}---")

                        except NameError:
                            pass

                        # Google Safebrowsing
                        try:
                            if 'Google Safebrowsing' in response_json['data']['attributes']['last_analysis_results']:
                                google_category = \
                                    response_json['data']['attributes']['last_analysis_results']['Google Safebrowsing'][
                                        'category']
                                google_method = \
                                    response_json['data']['attributes']['last_analysis_results']['Google Safebrowsing'][
                                        'method']
                                google_result = \
                                    response_json['data']['attributes']['last_analysis_results']['Google Safebrowsing'][
                                        'result']

                                print(f'{Fore.CYAN}Google Safebrowsing results:')
                                print(f'{Fore.MAGENTA}Category: {Fore.WHITE}{google_category}')
                                print(f'{Fore.MAGENTA}Result: {Fore.WHITE}{google_result}')
                                print(f'{Fore.MAGENTA}Method: {Fore.WHITE}{google_method}')

                            else:
                                print(f'{Fore.CYAN}Google Safebrowsing results: {Fore.WHITE}N/A')

                        except NameError:
                            pass

                    else:
                        print(f'Last analysis results: {Fore.WHITE}N/A')
                else:
                    pass

                print(f"{Fore.WHITE}--- End of VT analysis ---\n")

    # This is a function to get all relevant information about an IP address from AbuseIPDB
    def abuseipdb():
        ''' This is a function to get all relevant information about an IP address from AbuseIPDB '''

        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': api_key_abuseipdb
        }
        parameters = {
            'ipAddress': ip,
            'MaxAgeInDays': '182',
            'verbose': True
        }
        response = requests.get(url=url, headers=headers, params=parameters)
        json_data = json.loads(response.content)

        if 'data' not in json_data:
            print(f"\n{Fore.WHITE}--- Start of Abuse-IPDB analysis ---")
            print(f'{Fore.BLUE}No analysis available from Abuse-IPDB about: {Fore.CYAN}{ip}')
            print(f"{Fore.WHITE}--- End of Abuse-IPDB analysis ---\n")
        else:
            json_main = json_data['data']

            print(f"\n{Fore.WHITE}--- Start of Abuse-IPDB analysis ---")
            print(f'{Fore.BLUE}Abuse-IPDB analysis: {Fore.CYAN}{ip}')
            print(f"{Fore.WHITE}---")

            ipAddress = json_main['ipAddress']
            print(f'{Fore.MAGENTA}IP address: {Fore.WHITE}{ipAddress}')

            isPublic = json_main['isPublic']
            print(f'{Fore.MAGENTA}Is Public address? {Fore.WHITE}{isPublic}')

            isWhitelisted = json_main['isWhitelisted']
            print(f'{Fore.MAGENTA}Is whitelisted? {Fore.WHITE}{isWhitelisted}')

            abuseConfidenceScore = json_main['abuseConfidenceScore']
            print(f'{Fore.MAGENTA}Abuse confidence score: {Fore.WHITE}{abuseConfidenceScore}')

            countryCode = json_main['countryCode']
            print(f'{Fore.MAGENTA}Country code: {Fore.WHITE}{countryCode}')

            usageType = json_main['usageType']
            print(f'{Fore.MAGENTA}Usage type: {Fore.WHITE}{usageType}')

            isp = json_main['isp']
            print(f'{Fore.MAGENTA}ISP: {Fore.WHITE}{isp}')

            domain = json_main['domain']
            print(f'{Fore.MAGENTA}Domain: {Fore.WHITE}{domain}')

            hostnames = json_main['hostnames']
            print(f'{Fore.MAGENTA}Hostnames: {Fore.WHITE}{hostnames}')

            totalReports = json_main['totalReports']
            print(f'{Fore.MAGENTA}Total reports (last 182 days): {Fore.WHITE}{totalReports}')

            lastReportedAt = json_main['lastReportedAt']
            print(f'{Fore.MAGENTA}Last reported at: {Fore.WHITE}{lastReportedAt}')

            main_reports = json_main['reports']

            if args.verbose:
                if main_reports == []:
                    pass
                else:

                    print(f"{Fore.WHITE}---")
                    print(f'{Fore.BLUE}First report:')

                    reportedAt_one = main_reports[0]['reportedAt']
                    print(f'{Fore.MAGENTA}Reported at: {Fore.WHITE}{reportedAt_one}')

                    comment_one = main_reports[0]['comment']
                    print(f'{Fore.MAGENTA}Comment: {Fore.WHITE}{comment_one}')

                    reporterCountryCode_one = main_reports[0]['reporterCountryCode']
                    print(f'{Fore.MAGENTA}Reporter country code: {Fore.WHITE}{reporterCountryCode_one}')

                    reporterCountryName_one = main_reports[0]['reporterCountryName']
                    print(f'{Fore.MAGENTA}Reporter country name: {Fore.WHITE}{reporterCountryName_one}')

                if totalReports >= 2:
                    print(f"{Fore.WHITE}---")
                    print(f'{Fore.BLUE}Second report:')

                    reportedAt_sec = main_reports[1]['reportedAt']
                    print(f'{Fore.MAGENTA}Reported at: {Fore.WHITE}{reportedAt_sec}')

                    comment_sec = main_reports[1]['comment']
                    print(f'{Fore.MAGENTA}Comment: {Fore.WHITE}{comment_sec}')

                    reporterCountryCode_sec = main_reports[1]['reporterCountryCode']
                    print(f'{Fore.MAGENTA}Reporter country code: {Fore.WHITE}{reporterCountryCode_sec}')

                    reporterCountryName_sec = main_reports[1]['reporterCountryName']
                    print(f'{Fore.MAGENTA}Reporter country name: {Fore.WHITE}{reporterCountryName_sec}')
                else:
                    pass
            else:
                pass

            print(f"{Fore.WHITE}--- End of Abuse-IPDB analysis ---\n")

    # This is a function to get all relevant information about an IP address via WHOIS
    def whois_ip():
        ''' This is a function to get all relevant information about an IP address via WHOIS '''

        try:
            w = whois.whois(ip)

            if w.domain_name == None and w.registrar == None and w.referral_url == None and w.updated_date == None and w.creation_date == None and w.expiration_date == None and w.name == None and w.org == None and w.country == None and w.state == None and w.city == None and w.address ==None:
                print(f"{Fore.WHITE}\n--- Start of WHOIS analysis ---")
                print(f'{Fore.BLUE}No analysis available from WHOIS: {Fore.CYAN}{ip}')
                print(f"{Fore.WHITE}--- End of WHOIS analysis ---\n")
            else:

                print(f"{Fore.WHITE}\n--- Start of WHOIS analysis ---")
                print(f'{Fore.BLUE}WHOIS analysis: {Fore.CYAN}{ip}')
                print(f"{Fore.WHITE}---")

                try:
                    print(f'{Fore.MAGENTA}Domain name: {Fore.WHITE}{w.domain_name}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}Registrar: {Fore.WHITE}{w.registrar}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}Referral URL: {Fore.WHITE}{w.referral_url}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}Updated date: {Fore.WHITE}{w.updated_date}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}Creation date: {Fore.WHITE}{w.creation_date}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}Expiration date: {Fore.WHITE}{w.expiration_date}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}Name: {Fore.WHITE}{w.name}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}org: {Fore.WHITE}{w.org}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}country: {Fore.WHITE}{w.country}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}state: {Fore.WHITE}{w.state}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}city: {Fore.WHITE}{w.city}')
                except NameError:
                    pass

                try:
                    print(f'{Fore.MAGENTA}address: {Fore.WHITE}{w.address}')
                except NameError:
                    pass

                print(f"{Fore.WHITE}--- End of WHOIS analysis ---\n")

        except NameError:
            print(f"{Fore.WHITE}\n--- Start of WHOIS analysis ---")
            print(f'{Fore.BLUE}No analysis available from WHOIS about: {Fore.CYAN}{ip}')
            print(f"{Fore.WHITE}--- End of WHOIS analysis ---\n")

    # This is a function to get all relevant information about an IP address via SHODAN
    def shodan_ip():
        ''' This is a function to get all relevant information about an IP address via SHODAN '''

        api = shodan.Shodan(api_key_shodan)

        try:
            info = api.host(ip)

            if info == {}:
                print(f"{Fore.WHITE}\n--- Start of SHODAN analysis ---")
                print(f'{Fore.BLUE}No analysis available via SHODAN about: {Fore.CYAN}{ip}')
                print(f"{Fore.WHITE}--- End of SHODAN analysis ---\n")
            else:

                print(f"{Fore.WHITE}\n--- Start of SHODAN analysis ---")
                print(f'{Fore.BLUE}SHODAN analysis: {Fore.CYAN}{ip}')
                print(f"{Fore.WHITE}---")

                try:
                    city = info['city']
                    print(f'{Fore.MAGENTA}City: {Fore.WHITE}{city}')
                except:
                    pass

                try:
                    country_name = info['country_name']
                    print(f'{Fore.MAGENTA}Country name: {Fore.WHITE}{country_name}')
                except:
                    pass

                try:
                    country_code = info['country_code']
                    print(f'{Fore.MAGENTA}Country code: {Fore.WHITE}{country_code}')
                except:
                    pass

                try:
                    region_code = info['region_code']
                    print(f'{Fore.MAGENTA}Region code: {Fore.WHITE}{region_code}')
                except:
                    pass

                try:
                    hostnames = info['hostnames'][:4]
                    print(f'{Fore.MAGENTA}Hostnames: {Fore.WHITE}{hostnames}')
                except:
                    pass

                try:
                    os = info['os']
                    print(f'{Fore.MAGENTA}OS: {Fore.WHITE}{os}')
                except:
                    pass

                try:
                    tags = info['tags']
                    print(f'{Fore.MAGENTA}Tags: {Fore.WHITE}{tags}')
                except:
                    pass

                try:
                    ip_x = info['ip']
                    print(f'{Fore.MAGENTA}IP: {Fore.WHITE}{ip_x}')
                except:
                    pass

                try:
                    isp = info['isp']
                    print(f'{Fore.MAGENTA}ISP: {Fore.WHITE}{isp}')
                except:
                    pass

                try:
                    domains = info['domains']
                    print(f'{Fore.MAGENTA}Domains: {Fore.WHITE}{domains}')
                except:
                    pass

                if args.verbose:
                    try:
                        ports = info['ports']
                        print(f'{Fore.MAGENTA}Ports: {Fore.WHITE}{ports}')
                    except:
                        pass

                    try:
                        vulns = info['vulns'][:5]
                        print(f'{Fore.MAGENTA}Vulnerabilities: {Fore.WHITE}{vulns}')
                    except:
                        pass
                else:
                    pass

                print(f"{Fore.WHITE}--- End of SHODAN analysis ---\n")

        except:
            print(f"{Fore.WHITE}\n--- Start of SHODAN analysis ---")
            print(f'{Fore.BLUE}No analysis available via SHODAN about: {Fore.CYAN}{ip}')
            print(f"{Fore.WHITE}--- End of SHODAN analysis ---\n")

    # This is a for loop to iterate over to IP addresses in the list provided by the user
    for ip in ip_list:
        print(f"{Fore.LIGHTGREEN_EX}[+]  {Fore.GREEN}START of Reputation scans for: {Fore.WHITE}{ip}  {Fore.LIGHTGREEN_EX}[+]")
        virustotal_ip()
        abuseipdb()
        whois_ip()
        shodan_ip()
        print(f"{Fore.LIGHTRED_EX}[+]  {Fore.RED}END of reputation scans for: {Fore.WHITE}{ip}  {Fore.LIGHTRED_EX}[+]\n")

# If statement to determine which argument will execute each function
if args.hash_list:
    hash_reputation()
elif args.domain_list:
    domain_reputation()
elif args.url_list:
    url_reputation()
elif args.ip_list:
    ip_reputation()
else:
    # Help when no arguments are given
    print(f'{Fore.BLUE}For HELP execute: {Fore.WHITE}python main.py -h')







