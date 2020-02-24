#!/usr/bin/env python

__author__ = "DFIRSec (@pulsecode)"
__version__ = "1.7"
__description__ = "Script to retrieve subdomains from given domain."

import json
import os
import re
import sys
import time

import dns.exception
import dns.resolver
import requests
import validators
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from prettytable import PrettyTable

from termcolors import Termcolor as tc

email = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,5}$)"
ipv4 = re.compile(r"(?![0])\d{1,}\.\d{1,3}\.\d{1,3}\.(?![0])\d{1,3}")


def dns_lookup(domain):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = 2
    resolver.lifetime = 2
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']

    # fallback method if default dns lookup fails
    def fallback():
        url = f'https://dns.google.com/resolve?name={domain}&type=A'
        try:
            r = requests.get(url)
            r.raise_for_status()
            if r.json()['Answer']:
                answer = r.json()['Answer']
                if re.findall(ipv4, answer[0]['data']):
                    return answer[0]['data']
                elif re.findall(ipv4, answer[1]['data']):
                    return answer[1]['data']
            else:
                return False
        except requests.exceptions.RequestException as err:
            print(f"{tc.WARNING} Issue encountered:{tc.RESET}", err)
        except requests.exceptions.HTTPError as err:
            print(f"{tc.WARNING} Http Error:{tc.RESET}", err)
        except requests.exceptions.ConnectionError as err:
            print(f"{tc.WARNING} Error Connecting:{tc.RESET}", err)
        except requests.exceptions.Timeout as err:
            print(f"{tc.WARNING} Timeout Error:{tc.RESET}", err)
        except (KeyError, IndexError):
            pass

    try:
        answer = resolver.query(domain, 'A')
        return answer[0]
    except (dns.resolver.NoAnswer,
            dns.exception.Timeout,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers):
        return fallback()


def crt_get_subs(domain):
    url = f'https://crt.sh/?q=%25.{domain}'
    soup = ''
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        if r.status_code == 200:
            soup = BeautifulSoup(r.content, 'html.parser')
    except requests.exceptions.RequestException as err:
        sys.exit(f"{tc.WARNING} Issue encountered:{tc.RESET}", err)
    except requests.exceptions.HTTPError as err:
        print(f"{tc.WARNING} Http Error:{tc.RESET}", err)
    except requests.exceptions.ConnectionError as err:
        print(f"{tc.WARNING} Error Connecting:{tc.RESET}", err)
    except requests.exceptions.Timeout as err:
        print(f"{tc.WARNING} Timeout Error:{tc.RESET}", err)

    for tr in soup.find_all('tr')[2:]:
        td = tr.find_all('td')
        try:
            if '*' not in td[4].text:
                yield td[4].get_text(separator=" ").strip('\n')
        except:
            continue


def vt_get_subs(domain):
    url = f'https://www.virustotal.com/ui/domains/{domain}/subdomains'
    subd_regex = r"\"id\":\s\"(.*)\""
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        if r.status_code == 200:
            match = re.findall(subd_regex, r.text)
            yield match
    except requests.exceptions.RequestException as err:
        print(f"{tc.WARNING} Issue encountered:{tc.RESET}", err)
    except requests.exceptions.HTTPError as err:
        print(f"{tc.WARNING} Http Error:{tc.RESET}", err)
    except requests.exceptions.ConnectionError as err:
        print(f"{tc.WARNING} Error Connecting:{tc.RESET}", err)
    except requests.exceptions.Timeout as err:
        print(f"{tc.WARNING} Timeout Error:{tc.RESET}", err)


def main(domain):
    x = PrettyTable()
    x.field_names = ["Subdomain", "Domain", "Resolved"]
    x.align["Subdomain"] = "r"
    x.align["Domain"] = "l"
    x.align["Resolved"] = "l"
    x.sortby = "Subdomain"

    # subdomain recursive lookup
    subs = []
    for sub in crt_get_subs(domain):
        for item in sub.split(' '):
            subs.append(item)

    for sub in vt_get_subs(domain):
        for item in sub:
            subs.append(item)

    subset = set(subs)
    for sub in subset:
        if sub != domain and not re.search(email, sub):
            print(f'{tc.PROCESSING}  Discovered: {tc.BOLD}{sub.lower()}{tc.RESET}')
            start_time = time.time()
            ip = ''
            if dns_lookup(sub) is None:
                if time.time() - start_time > 2:
                    print(f'{tc.WARNING}  DNS lookup taking longer than expected...trying dns.google.com')
                    try:
                        ip = dns_lookup(domain).fallback()
                    except AttributeError:
                        pass
                else:
                    ip = f"{tc.GRAY}{dns_lookup(sub)}{tc.RESET}"
            else:
                ip = dns_lookup(sub)

            root = sub.split(domain)
            subdomain = f"{tc.BOLD}{''.join(root).lower()}{tc.RESET}"
            x.add_row([subdomain, domain, str(ip)])

    # check if rows contain data
    if x._rows:
        print(f"\n{x}")
    else:
        print("No data available for", domain)


if __name__ == "__main__":
    banner = '''
        _____       __       _______           __
       / ___/__  __/ /_     / ____(_)___  ____/ /__  _____
       \__ \/ / / / __ \   / /_  / / __ \/ __  / _ \/ ___/
      ___/ / /_/ / /_/ /  / __/ / / / / / /_/ /  __/ /
     /____/\__,_/_.___/  /_/   /_/_/ /_/\__,_/\___/_/
    '''
    print(tc.CYAN + banner + tc.RESET)
    
    if len(sys.argv) < 2:
        sys.exit("sub_finder.py: error: the following arguments are required: domain")
    else:
        domain = sys.argv[1]


    if validators.domain(domain):
        print(f"\n{tc.CYAN}Gathering subdomains...{tc.RESET}")
        main(domain)
    else:
        sys.exit(f"{tc.ERROR} {tc.BOLD}'{domain}'{tc.RESET} does not appear to be a valid domain.")
