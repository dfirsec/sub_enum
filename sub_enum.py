import asyncio
import contextlib
import re
import sys
import time
from typing import Iterable
from urllib.parse import urlparse

import aiohttp
import requests
from bs4 import BeautifulSoup
from dns import exception, name, resolver
from prettytable import PrettyTable
from requests.exceptions import HTTPError, Timeout
from termcolors import Termcolor

TC = Termcolor()

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.8"
__description__ = "Script to retrieve subdomains from given domain."

# regexes
EMAIL = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,5}$)"
IPV4 = re.compile(r"(?![0])\d+\.\d{1,3}\.\d{1,3}\.(?![0])\d{1,3}")
DOMAIN = r"([^\\n|\W|:|\.][A-Za-z0-9]+(?:[\-|\.|][A-Za-z0-9]+)*(?:\[\.\]|\.)(?![a-z-]*.[i\.e]$|[e\.g]$)(?:[a-z]{2,4})\b|(?:\[\.\][a-z]{2,4})(?!@)$)"

# filter out deprecation warnings
if not sys.warnoptions:
    import warnings

    warnings.filterwarnings("ignore", category=DeprecationWarning)


def valid_domain(domain: str) -> bool:
    """
    Returns `True` if the `domain` parameter is not `None` and matches the `DOMAIN` regular
    expression, otherwise it returns `False`

    :param domain: The domain name to validate
    :type domain: str
    :return: A boolean value.
    """
    pattern = re.compile(DOMAIN)
    return False if domain is None else bool(re.search(pattern, domain))


def connect(url: str):
    """
    Attempts to connect to the URL provided, and if successful, returns the response object

    :param url: The URL to connect to
    :return: A response object.
    """
    session = requests.Session()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}
    try:
        resp = session.get(url, timeout=10, headers=headers)
        resp.raise_for_status()
    except HTTPError as err:
        print(f"{TC.WARNING} HTTP Error:{TC.RESET} {err}")
    except Timeout as err:
        print(f"{TC.WARNING} Timeout encountered:{TC.RESET} {err}")
    except ConnectionError as err:
        print(f"{TC.WARNING} Connection Error:{TC.RESET} {err}")
    else:
        if resp.status_code == 200:
            return resp
    return None


async def async_connect(url: str):
    """
    Creates a session, then tries to get the url, and if successful, it returns the json.

    :param url: The URL to connect to
    :return: A list of dictionaries.
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}
    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.json()
        except aiohttp.ClientConnectorError as error:
            print("Connection Error:", error)


def dns_lookup(domain: str):
    """
    If the default dns lookup fails, it will use Google's dns lookup service.

    :param domain: The domain name you want to resolve
    :return: The IP address of the domain.
    """
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
    except (name.NameTooLong, name.LabelTooLong, name.EmptyLabel):
        pass


def crt_get_subs(domain: str) -> Iterable[str]:
    """
    Takes a domain name as input, and returns a generator of subdomains

    :param domain: The domain you want to find subdomains for
    """
    url = f"https://crt.sh/?q={domain}"
    with contextlib.suppress(Exception):
        content = connect(url).content  # type: ignore
        soup = BeautifulSoup(content, "lxml")
        table = soup.select("table")[1]
        for row in table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) > 1:
                yield cols[4].text.replace("*", "").strip(".*")


def certspotter_get_subs(domain: str) -> Iterable[str]:
    """
    Takes a domain name as an argument, and returns a generator of subdomains

    :param domain: The domain you want to search for subdomains
    """
    url = "https://api.certspotter.com/v1/issuances?domain="
    results = f"{url}{domain}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert"
    loop = asyncio.get_event_loop()
    grab = loop.run_until_complete(async_connect(results))
    with contextlib.suppress(Exception):
        lists = [name["dns_names"] for name in grab]  # type: ignore
        results = [y for x in lists for y in x] # combine lists
        for sub in results:
            if domain in sub:
                yield sub.replace("*.", "")


def web_archive(domain: str) -> Iterable[str]:
    """
    Takes a domain name as an argument, and returns a list of subdomains

    :param domain: The domain you want to search for
    :type domain: str
    """
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
        yield from list(set(subs))


def main(domain: str):
    """
    Takes a domain name as an argument, performs lookups, and returns a table of subdomains and
    their IP addresses.

    :param domain: The domain you want to enumerate
    """
    ptable = PrettyTable()
    ptable.field_names = ["Subdomain", "Domain", "Resolved"]
    ptable.align["Subdomain"] = "r"
    ptable.align["Domain"] = "l"
    ptable.align["Resolved"] = "l"
    ptable.sortby = "Subdomain"

    subs = []

    print(f"\n{TC.YELLOW}[ Trying Web Archive -- archive.org ]{TC.RESET}")
    for sub in web_archive(domain):
        subs.append(sub)
        print(f"{TC.PROCESSING}  Discovered: {TC.BOLD}{sub}{TC.RESET}")

    print(f"\n{TC.YELLOW}[ Performing Lookups -- takes a little longer ]{TC.RESET}")
    try:
        for sub in crt_get_subs(domain):
            subs.extend(iter(sub.split(" ")))

        if certspotter_get_subs(domain):
            subs.extend(iter(set(certspotter_get_subs(domain))))
        else:
            print(f"{TC.WARNING}  Certspotter might be throttling us...")

        subset = set(subs)
        for sub in subset:
            if sub != domain and not re.search(EMAIL, sub):
                print(f"{TC.PROCESSING}  Discovered: {TC.BOLD}{sub.lower()}{TC.RESET}")
                start_time = time.time()
                ip_addr = ""
                if dns_lookup(sub) is None:
                    if time.time() - start_time > 2:
                        print(f"{TC.WARNING}  DNS lookup taking longer than expected...trying dns.google.com")
                        with contextlib.suppress(AttributeError):
                            ip_addr = dns_lookup(domain).fallback()  # type: ignore

                    else:
                        ip_addr = f"{TC.GRAY}{dns_lookup(sub)}{TC.RESET}"
                else:
                    ip_addr = dns_lookup(sub)

                root = sub.split(domain)
                subdomain = f"{TC.BOLD}{''.join(root).lower()}{TC.RESET}"
                ptable.add_row([subdomain, domain, str(ip_addr)])

        if ptable._rows:
            print(f"\n{ptable}")
        else:
            print(f"No data available for {domain}")
    except KeyboardInterrupt:
        sys.exit("-- Exited --")


if __name__ == "__main__":
    BANNER = rf"""
      _____       __       ______
     / ___/__  __/ /_     / ____/___  __  ______ ___
     \__ \/ / / / __ \   / __/ / __ \/ / / / __ `__ \
    ___/ / /_/ / /_/ /  / /___/ / / / /_/ / / / / / /
   /____/\__,_/_.___/  /_____/_/ /_/\__,_/_/ /_/ /_/
   v{__version__}
    """
    print(TC.CYAN + BANNER + TC.RESET)

    if len(sys.argv) < 2:
        sys.exit("sub_enum.py: error: the following arguments are required: domain")
    else:
        DOM = sys.argv[1]

    if valid_domain(DOM):
        print(f"\n{TC.CYAN}Gathering subdomains...{TC.RESET}")
        try:
            main(DOM)
        except KeyboardInterrupt:
            sys.exit("-- Exited --")
    else:
        sys.exit(f"{TC.ERROR} {TC.BOLD}'{DOM}'{TC.RESET} does not appear to be a valid domain.")
