import asyncio
import contextlib
import re
import sys
import time
from urllib.parse import urlparse

import aiohttp
import requests
from bs4 import BeautifulSoup
from dns import exception, resolver
from prettytable import PrettyTable
from requests.exceptions import HTTPError, Timeout

from termcolors import Termcolor

tc = Termcolor()

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.6"
__description__ = "Script to retrieve subdomains from given domain."

# regexes
EMAIL = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,5}$)"
IPV4 = re.compile(r"(?![0])\d+\.\d{1,3}\.\d{1,3}\.(?![0])\d{1,3}")
DOMAIN = r"([A-Za-z0-9]+(?:[\-|\.|][A-Za-z0-9]+)*(?<!fireeye)(?:\[\.\]|\.)(?![a-z-]*.[i\.e]$|[e\.g]$)(?:[a-z]{2,4})\b|(?:\[\.\][a-z]{2,4})(?!@)$)"

# filter out deprecation warnings
if not sys.warnoptions:
    import warnings

    warnings.filterwarnings("ignore", category=DeprecationWarning)


def valid_domain(domain: str) -> bool:
    pattern = re.compile(DOMAIN)
    return False if domain is None else bool(re.search(pattern, domain))


def connect(url):
    session = requests.Session()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}
    try:
        resp = session.get(url, timeout=5, headers=headers)
        resp.raise_for_status()
    except HTTPError as err:
        print(f"{tc.WARNING} HTTP Error:{tc.RESET} {err}")
    except Timeout as err:
        print(f"{tc.WARNING} Timeout encountered:{tc.RESET} {err}")
    except ConnectionError as err:
        print(f"{tc.WARNING} Connection Error:{tc.RESET} {err}")
    else:
        if resp.status_code == 200:
            return resp
    return None


async def async_connect(url):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}
    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    results = await resp.json()
                    return results
        except aiohttp.ClientConnectorError as error:
            print("Connection Error:", error)


def dns_lookup(domain):
    resolve = resolver.Resolver(configure=False)
    resolve.timeout = 2  # type: ignore
    resolve.lifetime = 2  # type: ignore
    resolve.nameservers = [
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
    ]  # https://public-dns.info//nameservers.txt

    def fallback():
        """fallback method if default dns lookup fails."""
        url = f"https://dns.google.com/resolve?name={domain}&type=A"
        with contextlib.suppress(KeyError, IndexError):
            if not connect(url).json()["Answer"]:  # type: ignore
                return False
            answer = connect(url).json()["Answer"]  # type: ignore
            if re.findall(IPV4, answer[0]["data"]):
                return answer[0]["data"]
            if re.findall(IPV4, answer[1]["data"]):
                return answer[1]["data"]
        return None

    try:
        answer = resolver.resolve(domain, "A")
        return answer[0]
    except (
        resolver.NoAnswer,
        exception.Timeout,
        resolver.NXDOMAIN,
        resolver.NoNameservers,
    ):
        return fallback()


def bufferover_get_subs(domain):
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    with contextlib.suppress(Exception):
        fdns = list(connect(url).json()["FDNS_A"])  # type: ignore
        fdns_dom = [sub.split(",")[1] for sub in fdns]
        fdns_ip = [sub.split(",")[0] for sub in fdns]
        return dict(zip(fdns_dom, fdns_ip))


def crt_get_subs(domain):
    url = f"https://crt.sh/?q=%25.{domain}"
    with contextlib.suppress(Exception):
        content = connect(url).content  # type: ignore
        soup = BeautifulSoup(content, "lxml")
        for row in soup.find_all("tr")[2:]:
            data = row.find_all("td")
            if data and domain in data:
                yield data[4].get_text(separator=" ").replace("*", "").strip("\n")


def certspotter_get_subs(domain):
    url = "https://api.certspotter.com/v1/issuances?domain="
    results = f"{url}{domain}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert"
    loop = asyncio.get_event_loop()
    grab = loop.run_until_complete(async_connect(results))
    with contextlib.suppress(Exception):
        lists = [name["dns_names"] for name in grab]  # type: ignore
        results = [y for x in lists for y in x]
        for sub in results:
            if domain in sub:
                yield sub.replace("*.", "")


def web_archive(domain):
    url = "http://web.archive.org/cdx/search/cdx?url="
    results = f"{url}{domain}/&matchType=domain&output=json&fl=original&collapse=urlkey&limit=500000"
    loop = asyncio.get_event_loop()
    grab = loop.run_until_complete(async_connect(results))
    try:
        lists = list(grab)  # type: ignore
    except TypeError:
        print(f"No data available for {domain}")
    else:
        subs = [urlparse("".join(result)).netloc.replace(":80", "") for result in lists[1:]]
        for sub in list(set(subs)):
            print(f"{tc.PROCESSING}  Discovered: {tc.BOLD}{sub}{tc.RESET}")


def main(domain):  # sourcery no-metrics
    ptable = PrettyTable()
    ptable.field_names = ["Subdomain", "Domain", "Resolved"]
    ptable.align["Subdomain"] = "r"
    ptable.align["Domain"] = "l"
    ptable.align["Resolved"] = "l"
    ptable.sortby = "Subdomain"

    # subdomain lookup container
    subs = []

    print(f"{tc.YELLOW}[ Quick Results -- bufferover.run ]{tc.RESET}")
    try:
        for sub, result in list(sorted(bufferover_get_subs(domain).items())):  # type: ignore
            print(f"{sub:45}: {result}")
        subs.extend(sub for sub, _ in bufferover_get_subs(domain).items())  # type: ignore
    except AttributeError:
        print(f"No data available for {domain}")

    print(f"\n{tc.YELLOW}[ Trying Web Archive -- archive.org ]{tc.RESET}")
    web_archive(domain)

    print(f"\n{tc.YELLOW}[ Performing Lookups -- takes a little longer ]{tc.RESET}")
    try:
        for sub in crt_get_subs(domain):
            subs.extend(iter(sub.split(" ")))

        # if certspotter_get_subs(domain):
            # subs.extend(iter(set(certspotter_get_subs(domain))))
        # else:
        #     print(f"{tc.WARNING}  Certspotter might be throttling us...")
        subs.extend(iter(set(certspotter_get_subs(domain))))

        subset = set(subs)
        for sub in subset:
            if sub != domain and not re.search(EMAIL, sub):
                print(f"{tc.PROCESSING}  Discovered: {tc.BOLD}{sub.lower()}{tc.RESET}")
                start_time = time.time()
                ip_addr = ""
                if dns_lookup(sub) is None:
                    if time.time() - start_time > 2:
                        print(f"{tc.WARNING}  DNS lookup taking longer than expected...trying dns.google.com")
                        with contextlib.suppress(AttributeError):
                            ip_addr = dns_lookup(domain).fallback()  # type: ignore

                    else:
                        ip_addr = f"{tc.GRAY}{dns_lookup(sub)}{tc.RESET}"
                else:
                    ip_addr = dns_lookup(sub)

                root = sub.split(domain)
                subdomain = f"{tc.BOLD}{''.join(root).lower()}{tc.RESET}"
                ptable.add_row([subdomain, domain, str(ip_addr)])
        # check if rows contain data
        if ptable._rows:
            print(f"\n{ptable}")
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

    if valid_domain(dom):
        print(f"\n{tc.CYAN}Gathering subdomains...{tc.RESET}")
        main(dom)
    else:
        sys.exit(f"{tc.ERROR} {tc.BOLD}'{dom}'{tc.RESET} does not appear to be a valid domain.")
