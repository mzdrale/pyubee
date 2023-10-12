# PyUbee

Python library for getting stats from [Ubee routers](http://www.ubeeinteractive.com/products).

## Installation

You can install PyUbee from PyPi using `pip3 install pyubee`.

## Usage

To use within your Python scripts:
```python
from pyubee import Ubee

ubee = Ubee(
                host='192.168.1.1',
                username='admin',
                password='somepassword'
            )

if not ubee.session_active():
    ubee.login()

devices = ubee.get_connected_devices()

for x in devices:
    print('%s (%s)' % (x, devices[x]))

ubee.logout()
```

## CLI

A simple command line interface is available to query the router. The cli takes `host`, `username`, and `password` as mandatory arguments. The optional argument `model` can be used to specify the model of your router. If model is not specified, this tool will try to detect it automatically.

```
$ pyubee --help
usage: pyubee [-h] [--model MODEL] host username password

pyubee

positional arguments:
  host           Host
  username       Username
  password       Password

optional arguments:
  -h, --help     show this help message and exit
  --model MODEL  Model, supported models: EVW32C-0N, EVW3200-Wifi

$ pyubee 192.168.1.1 admin somepassword
AA:BB:CC:DD:EE:FF	192.168.1.10
FF:EE:DD:CC:BB:AA	192.168.1.11
```

## Notice

Ubee devices contain vulnerability which allows user to access Admin Web UI without logging in if someone else is logged in from the same IP address. For example if you have Ubee router (e.g. 192.168.1.1) in your home installed from your ISP and you have your own router (192.168.1.2) connected to it and you are doing NAT (Network Address Translation) on your router, then Ubee router will see all connections from clients connected to your router coming from the same IP address 192.168.1.2. In that scenario if someone logs into Ubee router Admin Web UI (http://192.168.1.1/UbeeLanSetup.asp) from Computer A, then anyone from Computer B or Computer C can access http://192.168.1.1/UbeeLanSetup.asp or any other page on 192.168.1.1 without logging in.

```
             +---------------+
             |               |
             |               |
             |     UBEE      |
             |               |
             |  192.168.1.1  |
             +-------+-------+
                     |
             +-------+-------+
             |  192.168.1.2  |
             |               |
             |  YOUR ROUTER  |
             |               |
             |   10.0.0.1    |
             +-------+-------+
                     |
      +-----------------------------+
      |              |              |
+-----+-----+  +-----+-----+  +-----+-----+
|  COMPUTER |  | COMPUTER  |  | COMPUTER  |
|     A     |  |     B     |  |     C     |
|           |  |           |  |           |
| 10.0.0.11 |  | 10.0.0.12 |  | 10.0.0.13 |
+-----------+  +-----------+  +-----------+
```

You should have this in your mind if you have similar setup.

Author of this package reported this issue to Vendor, even if [it's known for years](https://www.exploit-db.com/exploits/40156), but there is no response from Vendor and it looks like they are pushing firmware with the same vulnerability probably to all of their devices.

## Supported routers

This library was written for and tested with:

* Ambit EVW320B
* Ambit EVW321B
* Ubee DDW36C
* Ubee DVW32CB
* Ubee EVW32C-0S
* Ubee EVW32C-0N
* Ubee EVW3200-Wifi
* Ubee EVW3226 (UPC)
* Ubee UBC1303BA00
