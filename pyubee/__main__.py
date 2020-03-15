"""Run PyUbee from the command-line."""
import argparse
import logging
import sys

from pyubee import SUPPORTED_MODELS
from pyubee import Ubee


logging.basicConfig()
_LOGGER = logging.getLogger('pyubee')
_LOGGER.setLevel(logging.ERROR)
_LOGGER_TRAFFIC = logging.getLogger('pyubee.traffic')
_LOGGER_TRAFFIC.setLevel(logging.ERROR)


def main():
    """Scan for devices and print results."""
    parser = argparse.ArgumentParser(description='pyubee')
    parser.add_argument('host', help='Host')
    parser.add_argument('username', help='Username')
    parser.add_argument('password', help='Password')
    parser.add_argument('-m', '--model', default="detect",
                        help='Model, supported models: ' + ', '.join(SUPPORTED_MODELS))
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Enable debug-logging')
    parser.add_argument('-t', '--show-traffic', action='store_true',
                        help='Show sent/received traffic')
    args = parser.parse_args()

    if args.debug:
        _LOGGER.setLevel(logging.DEBUG)

    if args.show_traffic:
        _LOGGER_TRAFFIC.setLevel(logging.DEBUG)

    ubee = Ubee(host=args.host,
                username=args.username,
                password=args.password,
                model=args.model)

    if not ubee.session_active():
        if not ubee.login():
            print('Could not login')
            sys.exit(1)

    devices = ubee.get_connected_devices()

    if devices:
        print("Connected devices:")
        for device in devices:
            print("%s\t%s" % (device, devices[device]))
    else:
        print("No connected devices found")


if __name__ == '__main__':
    main()
