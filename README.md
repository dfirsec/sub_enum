# Subdomain Enumerator

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


Gathering subdomains...
[ Quick Results -- bufferover.run ]
www.example.com                              : 93.184.216.34

[ Trying Web Archive -- archive.org ]
⮩ Discovered: mumble.example.com
⮩ Discovered: user:pass@example.com
⮩ Discovered: prd.example.com
⮩ Discovered: assets.example.com
⮩ Discovered: my_name:my_password@www.example.com
⮩ Discovered: another.example.com
⮩ Discovered: cal.example.com
⮩ Discovered: the.example.com
⮩ Discovered: api.example.com
⮩ Discovered: gitlab-ci-token:xxxxxxxxxxxxxxxxxxxx@example.com
⮩ Discovered: old.example.com
⮩ Discovered: user:password@www.example.com
⮩ Discovered: migration.example.com
⮩ Discovered: username:password@example.com
⮩ Discovered: maps.example.com
⮩ Discovered: user%3apassword@example.com
⮩ Discovered: www.mozilla.org&item%3Dq:20933773d88383h2nf8dhdfjk3jk377d7djk3354@example.com
⮩ Discovered: myapp.example.com
⮩ Discovered: certs.example.com
⮩ Discovered: id:pw@example.com
⮩ Discovered: www.example.com
⮩ Discovered: user:password@example.com
⮩ Discovered: t.example.com
⮩ Discovered: 1.question.api.example.com
⮩ Discovered: 555-555-0199@example.com
⮩ Discovered: vendor.example.com
⮩ Discovered: somesite.example.com
⮩ Discovered: server.example.com
⮩ Discovered: cucm.example.com:8443
⮩ Discovered: cdni-ucdn.dcdn-1.example.com
⮩ Discovered: mailto:user@example.com
⮩ Discovered: host.subb.example.com
⮩ Discovered: mailto:youremail@example.com
⮩ Discovered: mailto:mail@example.com
⮩ Discovered: example.com
⮩ Discovered: linuxwarez:juarez@example.com
⮩ Discovered: shopping.example.com
⮩ Discovered: recipient@example.com
⮩ Discovered: mailto:someone@example.com
⮩ Discovered: bob:123456@www.example.com
⮩ Discovered: mailto:username@example.com
⮩ Discovered: soapserver1.example.com
⮩ Discovered: newserver.example.com
⮩ Discovered: mailto:p.dupond@example.com
⮩ Discovered: user:pw@example.com
⮩ Discovered: www.mozilla.org&item=q:20933773d88383h2nf8dhdfjk3jk377d7djk3354@example.com
⮩ Discovered: postalser.example.com
⮩ Discovered: mailto:spage@example.com
⮩ Discovered: mailto:example@example.com
⮩ Discovered: gooduser:secretpassword@www.example.com
⮩ Discovered: username@example.com
⮩ Discovered: mailto:friend@example.com
⮩ Discovered: in.example.com
⮩ Discovered: username:password@www.example.com
⮩ Discovered: ns1.example.com
⮩ Discovered: thetudors.example.com
⮩ Discovered: mailto:enter_your_friend_email@example.com
⮩ Discovered: alto.example.com
⮩ Discovered: labrador2.example.com
⮩ Discovered: jack:pass@www.example.com
⮩ Discovered: piwigo.example.com
⮩ Discovered: forum.example.com
⮩ Discovered: cdn.example.com
⮩ Discovered: mailto:name1@example.com
⮩ Discovered: othersite.example.com
⮩ Discovered: www.test.example.com
⮩ Discovered: www.EXAMPLE.com
⮩ Discovered: included.example.com
⮩ Discovered: svn.example.com
⮩ Discovered: info@example.com
⮩ Discovered: mailcard.example.com
⮩ Discovered: mailto:your-friend-email@example.com
⮩ Discovered: news.example.com
⮩ Discovered: customer.example.com
⮩ Discovered: xmpp:alice@example.com
⮩ Discovered: mailto:name@example.com
⮩ Discovered: mailto:email@example.com
⮩ Discovered: mailto:test@example.com
⮩ Discovered: foo.example.com
⮩ Discovered: shawonmasudrana.example.com
⮩ Discovered: ocsp.example.com
⮩ Discovered: me:secret@example.com
⮩ Discovered: log-on-username:log-on-password@www.example.com
⮩ Discovered: haservice.example.com
⮩ Discovered: zone1.example.com
⮩ Discovered: sales@example.com
⮩ Discovered: host.example.com
⮩ Discovered: www.example.com.
⮩ Discovered: wwww.example.com


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
