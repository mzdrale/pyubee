"""Module to communicate with Ubee routers."""

import re
import requests
import logging
import sys

_LOGGER = logging.getLogger(__name__)

_WIFI_DEVICES_REGEX = re.compile(
    r'<tr bgcolor=#[0-9a-fA-F]+>'
    r'<td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'
    r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2})</td>'
    r'<td>\d+</td><td>.+</td><td>\d+\.\d+\.\d+\.\d+</td><td>(.+)</td>'
    r'<td>.+</td><td>\d+</td></tr>'
)
_LAN_DEVICES_REGEX = re.compile(
    r'<tr bgcolor=#[0-9a-fA-F]+>'
    r'<td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'
    r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2})</td>'
    r'<td>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}</td>()'
)
_LOGIN_REGEX = re.compile(r'<title>Residential Gateway Login</title>')


class Ubee(object):
    """Represents a session to a Ubee Router."""

    def __init__(self, host=None, username=None, password=None):
        """Initialize a Netgear session."""

        self.host = host
        self.username = username
        self.password = password

    def session_active(self):
        """Check if session is active.""" 
        url = "http://{}/UbeeSysInfo.asp".format(self.host)
        try:
            response = requests.get(url, timeout=4)
        except:
            _LOGGER.error("Connection to the router failed.")
            return False

        title = _LOGIN_REGEX.findall(response.text)
        if title:
            return False

        return True

    def login(self):
        """Login to Ubee Admin interface."""
        url = "http://{}/goform/login".format(self.host)
        payload = {
            'loginUsername': self.username,
            'loginPassword': self.password
        }
        try:
            response = requests.post(url, data=payload, timeout=4)
        except:
            _LOGGER.error("Connection to the router failed.")
            return False

        title = _LOGIN_REGEX.findall(response.text)
        if title:
            _LOGGER.error("Logging into the router failed. "
                          "Check username and password.")
            return False

        if response.status_code == 200:
            return True

        return False

    def logout(self):
        """Logout from Admin interface"""
        url = "http://{}/logout.asp".format(self.host)
        try:
            response = requests.get(url, timeout=4)
        except:
            _LOGGER.error("Connection to the router failed.")
            return False

        if response.status_code == 200:
            return True

        return False

    def get_connected_devices(self):
        """Get list of connected devices"""
        url = "http://{}/UbeeAdvConnectedDevicesList.asp".format(self.host)
        try:
            response = requests.get(url, timeout=4)
        except requests.exceptions.Timeout:
            _LOGGER.error("Connection to the router failed.")
            return []

        data = response.text

        DEVICES = _WIFI_DEVICES_REGEX.findall(data) + _LAN_DEVICES_REGEX.findall(data)
        return {
            key: val for key, val in DEVICES
        }
