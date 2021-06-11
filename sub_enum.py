import asyncio
import re
import sys
import time
from urllib.parse import urlparse

import aiohttp
import dns.exception
import dns.resolver
import requests
import validators
from bs4 import BeautifulSoup
from prettytable import PrettyTable
from requests.exceptions import HTTPError, Timeout

from termcolors import Termcolor

tc = Termcolor()

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.5"
__description__ = "Script to retrieve subdomains from given domain."

# regexes
email = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,5}$)"
ipv4 = re.compile(r"(?![0])\d{1,}\.\d{1,3}\.\d{1,3}\.(?![0])\d{1,3}")


def connect(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}
        resp = requests.get(url, timeout=5, headers=headers)
        resp.raise_for_status()
        if resp.status_code == 200:
            return resp
    except HTTPError as err:
        print(f"{tc.WARNING} HTTP Error:{tc.RESET} {err}")
    except Timeout as err:
        print(f"{tc.WARNING} Timeout encountered:{tc.RESET} {err}")
    except ConnectionError as err:
        print(f"{tc.WARNING} Connection Error:{tc.RESET} {err}")
    except Exception as err:
        sys.exit(f"{tc.WARNING} Issue encountered:{tc.RESET} {err}")


async def async_connect(url):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}
    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    results = await resp.json()
                    return results
        except aiohttp.ClientConnectorError as e:
            print("Connection Error:", str(e))


def dns_lookup(domain):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = 2
    resolver.lifetime = 2
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]  # https://public-dns.info//nameservers.txt

    # fallback method if default dns lookup fails
    def fallback():
        url = f"https://dns.google.com/resolve?name={domain}&type=A"
        try:
            if connect(url).json()["Answer"]:
                answer = connect(url).json()["Answer"]
                if re.findall(ipv4, answer[0]["data"]):
                    return answer[0]["data"]
                if re.findall(ipv4, answer[1]["data"]):
                    return answer[1]["data"]
            else:
                return False
        except (KeyError, IndexError):
            pass

    try:
        answer = resolver.resolve(domain, "A")
        return answer[0]
    except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return fallback()


def bufferover_get_subs(domain):
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        connect(url).json(s)
    except Exception:
        pass
    else:
        fdns = list(connect(url).json()["FDNS_A"])
        fdns_dom = [sub.split(",")[1] for sub in fdns]
        fdns_ip = [sub.split(",")[0] for sub in fdns]
        fdns_res = dict(zip(fdns_dom, fdns_ip))
        return fdns_res


def crt_get_subs(domain):
    url = f"https://crt.sh/?q=%25.{domain}"
    soup = ""
    try:
        content = connect(url).content
        soup = BeautifulSoup(content, "lxml")

        for tr in soup.find_all("tr")[2:]:
            td = tr.find_all("td")
            if "*" not in td[4].text:
                yield td[4].get_text(separator=" ").strip("\n")
    except Exception:
        pass


def certspotter_get_subs(domain):
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert"
    try:
        loop = asyncio.get_event_loop()
        grab = loop.run_until_complete(async_connect(url))
    except Exception:
        pass
    else:
        try:
            lists = [name["dns_names"] for name in grab]
        except KeyError:
            pass
        else:
            results = [y for x in lists for y in x]
            for sub in results:
                if domain in sub and "*." not in sub:
                    yield sub


def web_archive(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/&matchType=domain&output=json&fl=original&collapse=urlkey&limit=500000"
    try:
        loop = asyncio.get_event_loop()
        grab = loop.run_until_complete(async_connect(url))
    except Exception:
        print(f"No data available for {domain}")
        pass
    else:
        lists = list(grab)
        subs = [urlparse("".join(result)).netloc.replace(":80", "") for result in lists[1:]]
        for sub in list(set(subs)):
            print(f"{tc.PROCESSING}  Discovered: {tc.BOLD}{sub}{tc.RESET}")


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
    try:
        [print(f"{sub:45}: {ip}") for (sub, ip) in sorted(bufferover_get_subs(domain).items())]
        for sub, _ in bufferover_get_subs(domain).items():
            subs.append(sub)
    except AttributeError:
        print(f"No data available for {domain}")

    print(f"\n{tc.YELLOW}[ Trying Web Archive -- archive.org ]{tc.RESET}")
    web_archive(domain)

    print(f"\n{tc.YELLOW}[ Performing Lookups -- takes a little longer ]{tc.RESET}")
    try:
        for sub in crt_get_subs(domain):
            for item in sub.split(" "):
                subs.append(item)
        if certspotter_get_subs(domain):
            for sub in set(certspotter_get_subs(domain)):
                subs.append(sub)
        else:
            print(f"{tc.WARNING}  Certspotter might be throttling us...")

        subset = set(subs)
        for sub in subset:
            if sub != domain and not re.search(email, sub):
                print(f"{tc.PROCESSING}  Discovered: {tc.BOLD}{sub.lower()}{tc.RESET}")
                start_time = time.time()
                ip = ""
                if dns_lookup(sub) is None:
                    if time.time() - start_time > 2:
                        print(f"{tc.WARNING}  DNS lookup taking longer than expected...trying dns.google.com")
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
            print(f"No data available for {domain}")
    except KeyboardInterrupt:
        sys.exit("-- Exited --")


if __name__ == "__main__":
    banner = rf"""
      _____       __       ______
     / ___/__  __/ /_     / ____/___  __  ______ ___
     \__ \/ / / / __ \   / __/ / __ \/ / / / __ `__ \
    ___/ / /_/ / /_/ /  / /___/ / / / /_/ / / / / / /
   /____/\__,_/_.___/  /_____/_/ /_/\__,_/_/ /_/ /_/
   v{__version__}
    """
    print(tc.CYAN + banner + tc.RESET)

    if len(sys.argv) < 2:
        sys.exit("sub_enum.py: error: the following arguments are required: domain")
    else:
        dom = sys.argv[1]

    if validators.domain(dom):
        print(f"\n{tc.CYAN}Gathering subdomains...{tc.RESET}")
        main(dom)
    else:
        sys.exit(f"{tc.ERROR} {tc.BOLD}'{dom}'{tc.RESET} does not appear to be a valid domain.")
