# PyUbee
Python library for getting stats from [Ubee routers](http://www.ubeeinteractive.com/products).

Installation
------------

You can install PyUbee from PyPi using `pip3 install pyubee`.

Usage
-----

To use within your Python scripts:
```python
from pyubee import Ubee

ubee = Ubee(
                host='192.168.1.1',
                username='admin',
                password='somepassword'
            )

if not ubee.session_active():
    ubee.login())

devices = ubee.get_connected_devices()

for x in devices:
    print('%s (%s)' % (x, devices[x]))
```

Supported routers
-----------------
This library was written for and tested with:

* Ubee EVW32C-0N
