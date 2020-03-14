# Subdomain Finder

![Generic badge](https://img.shields.io/badge/python-3.7-blue.svg) [![Twitter](https://img.shields.io/badge/Twitter-@pulsecode-blue.svg)](https://twitter.com/pulsecode)

`sub_enum.py` Retrieve subdomains from given domain

## Installation

```text
git clone https://github.com/dfirsec/sub_enum.git
cd sub_enum
pip install -r requirements.txt
```

## Usage

```console
python sub_enum.py example.com

      _____       __       ______
     / ___/__  __/ /_     / ____/___  __  ______ ___
     \__ \/ / / / __ \   / __/ / __ \/ / / / __ `__ \
    ___/ / /_/ / /_/ /  / /___/ / / / /_/ / / / / / /
   /____/\__,_/_.___/  /_____/_/ /_/\__,_/_/ /_/ /_/
   v1.8


Gathering subdomains...
[ Quick Results -- bufferover.run ]
www.example.com                              : 93.184.216.34

[ Performing Lookups -- takes a little longer ]
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
|          www. | example.com | 93.184.216.34   |
+---------------+-------------+-----------------+
```
