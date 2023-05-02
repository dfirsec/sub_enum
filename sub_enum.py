"""Script to retrieve subdomains from given domain."""

import asyncio
import contextlib
import re
import sys
import time
from typing import Any, Iterable, List, Optional, Set
from urllib.parse import urlparse

import aiohttp
import requests
from aiohttp.client_exceptions import ClientConnectorError
from bs4 import BeautifulSoup
from dns import exception, name, resolver
from prettytable import PrettyTable
from requests.exceptions import HTTPError, Timeout

from termcolors import BOLD, CYAN, ERROR, GRAY, PROCESSING, RESET, WARNING, YELLOW

author = "DFIRSec (@pulsecode)"
version = "0.0.8"

# regexes
EMAIL = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,5}$)"
IPV4 = re.compile(r"(?![0])\d+\.\d{1,3}\.\d{1,3}\.(?![0])\d{1,3}")
DOMAIN = (
    r"([^\\n|\W|:|\.][A-Za-z0-9]+(?:[\-|\.|][A-Za-z0-9]+)*(?:\[\.\]|\.)"
    r"(?![a-z-]*.[i\.e]$|[e\.g]$)(?:[a-z]{2,4})\b|(?:\[\.\][a-z]{2,4})(?!@)$)"
)


def valid_domain(domain: str) -> bool:
    """
    Domain name validation.

    Args:
        domain (str): The domain name to validate.

    Returns:
        bool: True if the domain is valid, False otherwise.
    """
    pattern = re.compile(DOMAIN)
    return False if domain is None else bool(re.search(pattern, domain))


def connect(url: str) -> Optional[requests.Response]:
    """
    Attempts to connect to the URL provided, and if successful, returns the response object.

    Args:
        url (str): The URL to connect to.

    Returns:
        A response object.
    """
    session = requests.Session()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}
    http_ok = 200
    try:
        resp = session.get(url, timeout=10, headers=headers)
        resp.raise_for_status()
    except HTTPError as err:
        print(f"{WARNING} HTTP Error:{RESET} {err}")
    except Timeout as err:
        print(f"{WARNING} Timeout encountered:{RESET} {err}")
    except ConnectionError as err:
        print(f"{WARNING} Connection Error:{RESET} {err}")
    else:
        return resp if resp.status_code == http_ok else None


async def fetch_url(url: str) -> Optional[requests.Response]:
    """
    Creates a session, then tries to get the url, and if successful, it returns the json.

    Args:
        url (str): The URL to connect to.

    Returns:
        A response object.
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}
    http_ok = 200
    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            async with session.get(url) as resp:
                if resp.status == http_ok:
                    return await resp.json()
        except ClientConnectorError as error:
            print("Connection Error:", error)


def fallback(domain: str) -> Optional[Any]:
    """Fallback method if default dns lookup fails.

    Args:
        domain (str): The domain name you want to resolve.

    Returns:
        The IP address of the domain.
    """
    url = f"https://dns.google.com/resolve?name={domain}&type=A"
    with contextlib.suppress(KeyError, IndexError):
        response = requests.get(url, timeout=10).json()
        answers = response.get("Answer", [])

        for answer in answers:
            ip_address = answer.get("data")
            if re.findall(IPV4, ip_address):
                return ip_address
    return None


def dns_resolver() -> resolver.Resolver:
    """
    Returns a DNS resolver object with specific timeout, lifetime, and nameserver settings.

    Returns:
        An instance of the `resolver.Resolver` class with specific configurations for timeout,
        lifetime, and nameservers.
    """
    result = resolver.Resolver(configure=False)
    result.timeout = 2
    result.lifetime = 2
    result.nameservers = [
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
    ]

    return result


def dns_lookup(domain: str) -> Optional[Any]:
    """
    If the default dns lookup fails, it will use Google's dns lookup service.

    Args:
        domain (str): The domain name you want to resolve.

    Returns:
        The IP address of the domain.
    """
    resolve = dns_resolver()

    try:
        answers = resolve.resolve(domain, "A")
        return answers[0] if answers else None
    except (
        resolver.NoAnswer,
        exception.Timeout,
        resolver.NXDOMAIN,
        resolver.NoNameservers,
    ):
        return fallback(domain)
    except (name.NameTooLong, name.LabelTooLong, name.EmptyLabel):
        return None


def crt_get_subs(domain: str) -> Iterable[str]:
    """
    Takes a domain name as an argument, and returns a generator of subdomains from crt.sh.

    Args:
        domain (str): The domain you want to find subdomains for.

    Yields:
        A generator of subdomains.
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
    Takes a domain name as an argument, and returns a generator of subdomains from certspotter.

    Args:
        domain: The domain you want to search for subdomains.

    Yields:
        A generator of subdomains.
    """
    url = "https://api.certspotter.com/v1/issuances?domain="
    results = f"{url}{domain}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert"

    grab = asyncio.run(fetch_url(url))

    with contextlib.suppress(Exception):
        dns_lists = [name["dns_names"] for name in grab]  # type: ignore
        results = [dns_name for dns_list in dns_lists for dns_name in dns_list]  # combine the lists

        for sub in results:
            if domain in sub:
                yield sub.replace("*.", "")


def web_archive(domain: str) -> Iterable[str]:
    """
    Takes a domain name as an argument, and returns a list of subdomains.

    Args:
        domain (str): The domain you want to search for

    Yields:
        A generator of subdomains.
    """
    url = "http://web.archive.org/cdx/search/cdx?url="
    results = f"{url}{domain}/&matchType=domain&output=json&fl=original&collapse=urlkey&limit=500000"

    grab = asyncio.run(fetch_url(results))

    try:
        lists = list(grab)  # type: ignore
    except TypeError:
        print(f"No data available for {domain}")
    else:
        subs = [urlparse("".join(result)).netloc.replace(":80", "") for result in lists[1:]]
        yield from list(set(subs))


def print_discovered_subdomains(subs: List[str], domain: str) -> List[str]:
    """
    Prints each discovered subdomain and returns the list of subdomains.

    Args:
        subs (List[str]): A list of discovered subdomains (strings).
        domain (str): The domain parameter is a string representing the main domain name.

    Returns:
        A list of discovered subdomains.
    """
    subdomains = []
    for sub in subs:
        subdomains.append(sub)
        print(f"{PROCESSING}  Discovered: {BOLD}{sub}{RESET}")
    return subdomains


def add_subdomains_to_table(ptable: PrettyTable, subset: Set[str], domain: str) -> None:
    """
    Adds discovered subdomains to a PrettyTable object with corresponding domain and IP.

    Args:
        ptable (PrettyTable): Table to add the subdomains to.
        subset (Set[str]): A set of subdomains to be added to the table.
        domain (str): The main domain that the subdomains belong to.
    """
    for sub in subset:
        if sub != domain and not re.search(EMAIL, sub):
            print(f"{PROCESSING}  Discovered: {BOLD}{sub.lower()}{RESET}")
            start_time = time.time()
            ip_addr = dns_lookup(sub)

            if ip_addr is None:
                if time.time() - start_time > 2:
                    print(f"{WARNING}  DNS lookup taking longer than expected...trying dns.google.com")
                    with contextlib.suppress(AttributeError):
                        ip_addr = dns_lookup(domain).fallback()  # type: ignore # noqa: WPS220
                else:
                    ip_addr = f"{GRAY}{ip_addr}{RESET}"

            root = sub.split(domain)
            subdomain = f"{BOLD}{''.join(root).lower()}{RESET}"
            ptable.add_row([subdomain, domain, str(ip_addr)])


def main(domain: str) -> None:  # noqa: WPS213
    """
    Performs subdomain enumeration using various sources and displays the results.

    Args:
        domain (str): The domain you want to search for subdomains.
    """
    ptable = PrettyTable()
    ptable.field_names = ["Subdomain", "Domain", "Resolved"]
    ptable.align["Subdomain"] = "r"
    ptable.align["Domain"] = "l"
    ptable.align["Resolved"] = "l"
    ptable.sortby = "Subdomain"

    subs = []

    print(f"\n{YELLOW}[ Trying Web Archive -- archive.org ]{RESET}")
    subs = print_discovered_subdomains(list(web_archive(domain)), domain)

    print(f"\n{YELLOW}[ Performing Lookups -- takes a little longer ]{RESET}")
    try:  # noqa: WPS229
        for sub in crt_get_subs(domain):
            subs.extend(iter(sub.split(" ")))

        if certspotter_get_subs(domain):
            subs.extend(iter(set(certspotter_get_subs(domain))))
        else:
            print(f"{WARNING}  Certspotter might be throttling us...")

        subset = set(subs)
        add_subdomains_to_table(ptable, subset, domain)

        if ptable.get_string() != "":  # noqa: WPS504
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
   v{version}
    """
    print(CYAN + BANNER + RESET)

    if len(sys.argv) < 2:
        sys.exit("sub_enum.py: error: the following arguments are required: domain")
    else:
        DOM = sys.argv[1]

    if valid_domain(DOM):
        print(f"\n{CYAN}Gathering subdomains...{RESET}")
        try:
            main(DOM)
        except KeyboardInterrupt:
            sys.exit("-- Exited --")
    else:
        sys.exit(f"{ERROR} {BOLD}'{DOM}'{RESET} does not appear to be a valid domain.")
