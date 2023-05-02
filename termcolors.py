"""Colorama color codes and unicode symbols."""

from colorama import Fore, Style, init


# Unicode Symbols and colors
init()

CYAN = Fore.CYAN + Style.BRIGHT
GREEN = Fore.GREEN
GRAY = Fore.BLACK + Style.BRIGHT
YELLOW = Fore.LIGHTYELLOW_EX
WARNING = f"{Fore.YELLOW}\u0021{Style.RESET_ALL}"
ERROR = f"{Fore.RED}\u2718{Style.RESET_ALL}"
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT
PROCESSING = f"{Fore.GREEN}\u2BA9{Style.RESET_ALL}"
