"""Script to retrieve subdomains from given domain."""

import asyncio
import re
import sys
from collections.abc import AsyncGenerator
from collections.abc import Callable
from urllib.parse import urlparse

import aiohttp
import dns.asyncresolver
import dns.exception
from bs4 import BeautifulSoup
from rich.console import Console
from rich.console import Group
from rich.live import Live
from rich.progress import Progress
from rich.progress import SpinnerColumn
from rich.progress import TextColumn
from rich.table import Table
from rich.tree import Tree

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.1.2"

# Constants
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,5}$")
IPV4_REGEX = re.compile(r"(?![0])\d+\.\d{1,3}\.\d{1,3}\.(?![0])\d{1,3}")
DOMAIN_REGEX = re.compile(
    r"([^\\n|\W|:|\.][A-Za-z0-9]+(?:[\-|\.|][A-Za-z0-9]+)*(?:\[\.\]|\.)"
    r"(?![a-z-]*.[i\.e]$|[e\.g]$)(?:[a-z]{2,4})\b|(?:\[\.\][a-z]{2,4})(?!@)$)",
)

console = Console(highlight=False)


def validate_domain(domain: str) -> bool:
    """Validate the given domain name.

    Args:
        domain (str): The domain name to validate.

    Returns:
        bool: True if the domain is valid, False otherwise.
    """
    return bool(DOMAIN_REGEX.search(domain)) if domain else False


async def async_dns_lookup(domain: str) -> str | None:
    """Perform asynchronous DNS lookup for the given domain using dnspython.

    Args:
        domain (str): The domain name to resolve.

    Returns:
        Optional[str]: The IP address of the domain if found, None otherwise.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.lifetime = 5  # timeout in seconds

    try:
        answers = await resolver.resolve(domain, "A")
        return str(answers[0]) if answers else None
    except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout:
        return await fallback_dns_lookup(domain)
    except dns.exception.DNSException:
        return None


async def fallback_dns_lookup(domain: str) -> str | None:
    """Fallback method for DNS lookup using Google's DNS service.

    Args:
        domain (str): The domain name to resolve.

    Returns:
        Optional[str]: The IP address of the domain if found, None otherwise.
    """
    url = f"https://dns.google.com/resolve?name={domain}&type=A"
    if response := await fetch_url(url):
        for answer in response.get("Answer", []):
            ip_address = answer.get("data")
            if IPV4_REGEX.match(ip_address):
                return ip_address
    return None


async def fetch_url(url: str) -> dict | None:
    """Asynchronously fetch JSON data from a given URL.

    Returns:
        Optional[dict]: The JSON response if successful, None otherwise.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0",
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            async with asyncio.timeout(10):
                async with session.get(url) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except aiohttp.ClientError as error:
            console.print(f"[bold red]Connection Error:[/] {error}")
        except TimeoutError:
            return None
    return None


async def crt_get_subs(domain: str) -> AsyncGenerator[str]:
    """Retrieve subdomains from crt.sh.

    Yields:
        str: Discovered subdomains.
    """
    url = f"https://crt.sh/?q={domain}"
    subdomains = []
    async with aiohttp.ClientSession() as session, session.get(url) as response:
        if response.status == 200:
            content = await response.text()
            soup = BeautifulSoup(content, "lxml")
            table = soup.select("table")[1]
            for row in table.find_all("tr")[1:]:
                cols = row.find_all("td")
                if len(cols) > 1:
                    subdomains.append(cols[4].text.replace("*", "").strip(".*"))

    for subdomain in subdomains:
        yield subdomain


async def certspotter_get_subs(domain: str) -> AsyncGenerator[str]:
    """Retrieve subdomains from certspotter.

    Yields:
        str: Discovered subdomains.
    """
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    response = await fetch_url(url)

    if response:
        dns_lists = [name["dns_names"] for name in response]
        for dns_name in (name for dns_list in dns_lists for name in dns_list):
            if domain in dns_name:
                yield dns_name.replace("*.", "")


async def web_archive(domain: str) -> AsyncGenerator[str]:
    """Retrieve subdomains from web.archive.org.

    Yields:
        str: Discovered subdomains.
    """
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/&matchType=domain&output=json&fl=original&collapse=urlkey&limit=500000"
    response = await fetch_url(url)

    if response:
        for result in response[1:]:
            yield urlparse("".join(result)).netloc.replace(":80", "")
    else:
        console.print(f"[yellow]No data available for {domain} from web.archive.org[/]")


def print_discovered_subdomains(subs: set[str], source: str) -> None:
    """Print discovered subdomains."""
    tree = Tree(f"\n:mag_right: [green]Discovered with {source}")
    for sub in sorted(subs):
        tree.add(sub)
    console.print(tree)


async def add_subdomains_to_table(table: Table, subs: set[str], domain: str) -> None:
    """Add subdomains to a table.

    Args:
        table (Table): The table to add the subdomains to.
        subs (set[str]): The set of subdomains to iterate over.
        domain (str): The main domain.
    """
    for sub in sorted(subs):
        if sub != domain and not EMAIL_REGEX.search(sub):
            ip_addr = await async_dns_lookup(sub) or "N/A"
            subdomain = "".join(sub.split(domain)).lower().replace(".", "")
            table.add_row(subdomain, domain, str(ip_addr))


async def main(domain: str) -> None:
    """Perform subdomain enumeration using various sources.

    Args:
        domain (str): The domain to search for subdomains.
    """
    table = Table(title="Discovered Subdomains", show_header=True, header_style="bold magenta")
    table.add_column("Subdomain", style="cyan")
    table.add_column("Domain", style="magenta")
    table.add_column("Resolved", style="green")

    subs = set()
    progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True)

    overall_progress = progress.add_task("Enumerating subdomains...", total=4)

    async def search_and_print(source_func: Callable, source_name: str) -> set[str]:
        """Search for subdomains using a given source function.

        Returns:
            set[str]: A set of discovered subdomains.
        """
        task = progress.add_task(f"Searching {source_name}...")
        source_subs = {sub async for sub in source_func(domain)}
        progress.update(task, completed=True)
        progress.remove_task(task)
        progress.update(overall_progress, advance=1)
        if source_subs:
            subs.update(source_subs)
            print_discovered_subdomains(source_subs, source_name)
        return source_subs

    with Live(Group(progress), transient=True, console=console) as live:
        _archive_subs = await search_and_print(web_archive, "Web Archive")
        _crt_subs = await search_and_print(crt_get_subs, "crt.sh")
        certspotter_subs = await search_and_print(certspotter_get_subs, "Certspotter")

        if not certspotter_subs:
            live.console.print("[yellow]Certspotter might be throttling us...[/]")

        dns_task = progress.add_task("Performing DNS Lookups...", total=len(subs))
        for sub in subs:
            if sub != domain and not EMAIL_REGEX.search(sub):
                ip_addr = await async_dns_lookup(sub) or "N/A"
                subdomain = "".join(sub.split(domain)).lower().replace(".", "")
                table.add_row(subdomain, domain, str(ip_addr))
            progress.update(dns_task, advance=1)

        progress.update(overall_progress, completed=True)

    if table.row_count > 0:
        print("\n")
        console.print(table)
    else:
        console.print(f"[red]No data available for {domain}[/]")


if __name__ == "__main__":
    BANNER = f"""
      _____       __       ______
     / ___/__  __/ /_     / ____/___  __  ______ ___
     \\__ \\/ / / / __ \\   / __/ / __ \\/ / / / __ `__
    ___/ / /_/ / /_/ /  / /___/ / / / /_/ / / / / / /
   /____/\\__,_/_.___/  /_____/_/ /_/\\__,_/_/ /_/ /_/
   v{__version__}
    """

    console.print(BANNER, style="green")

    if len(sys.argv) < 2:
        console.print(f"[bold red]Usage: python {sys.argv[0]} <domain>[/]")
        sys.exit(1)

    target_domain = sys.argv[1]

    if validate_domain(target_domain):
        console.print("[cyan]Gathering subdomains...[/]")
        try:
            asyncio.run(main(target_domain))
        except KeyboardInterrupt:
            console.print("[bold red]-- Exited --[/]")
            sys.exit(1)
    else:
        console.print(f"[bold red]'{target_domain}' does not appear to be a valid domain.[/]")
        sys.exit(1)
