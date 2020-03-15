#!/usr/bin/env python

__author__ = "DFIRSec (@pulsecode)"
__version__ = "1.8"
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
from requests.exceptions import (ConnectTimeout, HTTPError, RequestException,
                                 Timeout)

from termcolors import Termcolor as tc

email = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,5}$)"
ipv4 = re.compile(r"(?![0])\d{1,}\.\d{1,3}\.\d{1,3}\.(?![0])\d{1,3}")


def connect(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}  # nopep8
        resp = requests.get(url, timeout=5, headers=headers)
        resp.raise_for_status()
        if resp.status_code == 200:
            return resp
    except HTTPError as err:
        print(f"{tc.WARNING} HTTP Error:{tc.RESET}", err)
    except Timeout as err:
        print(f"{tc.WARNING} Timeout encountered:{tc.RESET}", err)
    except ConnectionError as err:
        print(f"{tc.WARNING} Connection Error:{tc.RESET}", err)
    except RequestException as err:
        sys.exit(f"{tc.WARNING} Issue encountered:{tc.RESET}", err)


def dns_lookup(domain):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = 2
    resolver.lifetime = 2
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']

    # fallback method if default dns lookup fails
    def fallback():
        url = f'https://dns.google.com/resolve?name={domain}&type=A'
        try:
            if connect(url).json()['Answer']:
                answer = connect(url).json()['Answer']
                if re.findall(ipv4, answer[0]['data']):
                    return answer[0]['data']
                elif re.findall(ipv4, answer[1]['data']):
                    return answer[1]['data']
            else:
                return False
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


def bufferover_get_subs(domain):
    url = f'https://dns.bufferover.run/dns?q=.{domain}'
    try:
        if connect(url).json():
            # forward dns = domain to ip
            fdns = [sub for sub in connect(url).json()['FDNS_A']]
            fdns_dom = [sub.split(',')[1] for sub in fdns]
            fdns_ip = [sub.split(',')[0] for sub in fdns]
            fdns_res = dict(zip(fdns_dom, fdns_ip))

        #     # reverse dns =  ip to domain
        #     if connect(url).json()['RDNS']:
        #         rdns = [sub for sub in connect(url).json()['RDNS']]
        #         rdns_dom = [sub.split(',')[1] for sub in rdns]
        #         rdns_ip = [sub.split(',')[0] for sub in rdns]
        #         rdns_res = dict(zip(rdns_dom, rdns_ip))

        # # combine dicts
        # if rdns_res:
        #     combined = {**fdns_res, **rdns_res}
        #     return combined
        # else:
        #     return fdns_res

        return fdns_res
    except Exception:
        pass


def crt_get_subs(domain):
    url = f'https://crt.sh/?q=%25.{domain}'
    soup = ''
    try:
        content = connect(url).content
        soup = BeautifulSoup(content, 'html.parser')

        for tr in soup.find_all('tr')[2:]:
            td = tr.find_all('td')
            if '*' not in td[4].text:
                yield td[4].get_text(separator=" ").strip('\n')
    except Exception:
        pass


def certspotter_get_subs(domain):
    url = f'https://certspotter.com/api/v0/certs?domain={domain}'
    try:
        if connect(url).json():
            lists = [name['dns_names'] for name in connect(url).json()]
            results = [y for x in lists for y in x]
            for sub in results:
                if domain in sub and '*.' not in sub:
                    yield sub
        else:
            return False
    except Exception:
        pass


def vt_get_subs(domain):
    url = f'https://www.virustotal.com/ui/domains/{domain}/subdomains'
    subd_regex = r"\"id\":\s\"(.*)\""
    try:
        match = re.findall(subd_regex, connect(url).text)
        yield match
    except Exception:
        pass


def main(domain):
    x = PrettyTable()
    x.field_names = ["Subdomain", "Domain", "Resolved"]
    x.align["Subdomain"] = "r"
    x.align["Domain"] = "l"
    x.align["Resolved"] = "l"
    x.sortby = "Subdomain"

    # subdomain lookup container
    subs = []

    print(f"{tc.YELLOW}[ Quick Results -- bufferover.run ]{tc.RESET}")
    [print(f"{sub:45}: {ip}") for (sub, ip) in sorted(bufferover_get_subs(domain).items())]  # nopep8
    for sub, _ in bufferover_get_subs(domain).items():
        subs.append(sub)

    print(f'\n{tc.YELLOW}[ Performing Lookups -- takes a little longer ]{tc.RESET}')  # nopep8
    for sub in crt_get_subs(domain):
        for item in sub.split(' '):
            subs.append(item)

    if certspotter_get_subs(domain):
        for sub in set(certspotter_get_subs(domain)):
            subs.append(sub)
    else:
        print(f"{tc.WARNING}  Looks like certspotter is throttling us...")

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
                    print(f'{tc.WARNING}  DNS lookup taking longer than expected...trying dns.google.com')  # nopep8
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
        print(f"No data available for '{domain}'")


if __name__ == "__main__":
    banner = rf'''
      _____       __       ______
     / ___/__  __/ /_     / ____/___  __  ______ ___
     \__ \/ / / / __ \   / __/ / __ \/ / / / __ `__ \
    ___/ / /_/ / /_/ /  / /___/ / / / /_/ / / / / / /
   /____/\__,_/_.___/  /_____/_/ /_/\__,_/_/ /_/ /_/
   v{__version__}
    '''
    print(tc.CYAN + banner + tc.RESET)

    if len(sys.argv) < 2:
        sys.exit("sub_enum.py: error: the following arguments are required: domain")
    else:
        domain = sys.argv[1]

    if validators.domain(domain):
        print(f"\n{tc.CYAN}Gathering subdomains...{tc.RESET}")
        main(domain)
    else:
        sys.exit(f"{tc.ERROR} {tc.BOLD}'{domain}'{tc.RESET} does not appear to be a valid domain.")  # nopep8
