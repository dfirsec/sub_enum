# Subdomain Finder

![Generic badge](https://img.shields.io/badge/python-3.7-blue.svg) [![Twitter](https://img.shields.io/badge/Twitter-@pulsecode-blue.svg)](https://twitter.com/pulsecode)

`sub_finder.py` Retrieve subdomains from given domain

## Installation

```text
git clone https://github.com/dfirsec/sub_finder.git
cd sub_finder
pip install -r requirements.txt
```

## Example Run

```console
python sub_finder.py example.com

        _____       __       _______           __
       / ___/__  __/ /_     / ____(_)___  ____/ /__  _____
       \__ \/ / / / __ \   / /_  / / __ \/ __  / _ \/ ___/
      ___/ / /_/ / /_/ /  / __/ / / / / / /_/ /  __/ /
     /____/\__,_/_.___/  /_/   /_/_/ /_/\__,_/\___/_/

Gathering subdomains...
⮩  Discovered: nowhereatall.example.com
⮩  Discovered: konferencje.example.com
⮩  Discovered: dev.example.com
⮩  Discovered: api.example.com
⮩  Discovered: ftp.example.com
⮩  Discovered: www.example.com
⮩  Discovered: ns2.example.com
⮩  Discovered: m.testexample.com
⮩  Discovered: conference.example.com
⮩  Discovered: gate.example.com
⮩  Discovered: ns1.example.com
⮩  Discovered: sales.example.com
⮩  Discovered: support.example.com
⮩  Discovered: products.example.com

+---------------+-------------+-----------------+
|     Subdomain | Domain      | Resolved        |
+---------------+-------------+-----------------+
|          api. | example.com | None            |
|   conference. | example.com | None            |
|          dev. | example.com | None            |
|          ftp. | example.com | None            |
|         gate. | example.com | None            |
|  konferencje. | example.com | None            |
|        m.test | example.com | 69.172.201.153  |
| nowhereatall. | example.com | None            |
|          ns1. | example.com | None            |
|          ns2. | example.com | None            |
|     products. | example.com | None            |
|        sales. | example.com | None            |
|      support. | example.com | None            |
|          www. | example.com | 199.168.151.251 |
+---------------+-------------+-----------------+
```
