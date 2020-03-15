#!/usr/bin/env python

from colorama import Fore, Style, init

init()


class Termcolor:
    # Unicode Symbols and colors
    CYAN = Fore.CYAN + Style.BRIGHT
    GREEN = Fore.GREEN
    GRAY = Fore.BLACK + Style.BRIGHT
    YELLOW = Fore.LIGHTYELLOW_EX
    WARNING = Fore.YELLOW + "\u0021" + Style.RESET_ALL
    ERROR = Fore.RED + "\u2718" + Style.RESET_ALL
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
    PROCESSING = Fore.GREEN + "\u2BA9" + Style.RESET_ALL
