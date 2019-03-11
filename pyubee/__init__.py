"""Module to communicate with Ubee routers."""

import logging
import re
import sys

import requests
from requests.exceptions import RequestException


_LOGGER = logging.getLogger(__name__)

MODELS = {
    'EVW32C-0N': {
        'url_session_active': '/UbeeSysInfo.asp',
        'url_login': '/goform/login',
        'url_logout': '/logout.asp',
        'url_connected_devices_lan': '/UbeeAdvConnectedDevicesList.asp',
        'url_connected_devices_wifi': '/UbeeAdvConnectedDevicesList.asp',
        'regex_login': re.compile(r'<title>Residential Gateway Login</title>'),
        'regex_wifi_devices': re.compile(
            r'<tr bgcolor=#[0-9a-fA-F]+>'
            r'<td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:' # mac address
            r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2})</td>'  # mac address, cont'd
            r'<td>\d+</td>'  # age
            r'<td>.+</td>'  # rssi
            r'<td>\d+\.\d+\.\d+\.\d+</td>'  # ip address
            r'<td>(.+)</td>'  # hostname
            r'<td>.+</td>'  # mode
            r'<td>\d+</td>'  # speed
            r'</tr>'
        ),
        'regex_lan_devices': re.compile(
            r'<tr bgcolor=#[0-9a-fA-F]+>'
            r'<td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'  # mac address
            r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2})</td>'  # mac address, cont'd
            r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>'  # ip address
        ),
    },
    'EVW3200-Wifi': {
        'url_session_active': '/BasicStatus.asp',
        'url_login': '/goform/loginMR3',
        'url_logout': '/logout.asp',
        'url_connected_devices_lan': '/RgDhcp.asp',
        'url_connected_devices_wifi': '/wlanAccess.asp',
        'regex_login': re.compile(r'<title>Residential Gateway Login</title>'),
        'regex_wifi_devices': re.compile(
            r'<tr bgcolor=#[0-9a-fA-F]+>'
            r'<td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:' # mac address
            r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2})</td>'  # mac address, cont'd
            r'<td>\d+</td>'  # age
            r'<td>.+</td>'  # rssi
            r'<td>.*</td>'  # ip address
            r'<td>(.+)?</td>'  # hostname
            r'<td>.+</td>'  # mode
            r'<td>\d+</td>'  # speed
            r'</tr>'
        ),
        'regex_lan_devices': re.compile(
            r'<tr bgcolor=#[0-9a-fA-F]+>'
            r'<td>([0-9a-fA-F]{12})</td>'  # mac address
            r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>'  # ip address
        ),
    },
}

SUPPORTED_MODELS = MODELS.keys()


class Ubee:
    """Represents a session to a Ubee Router."""

    def __init__(self, host=None, username=None, password=None, model='EVW32C-0N'):
        """Initialize a Ubee session."""

        if model not in MODELS:
            raise LookupError('Unknown model')

        self.host = host
        self.username = username
        self.password = password
        self.model = model
        self._model_info = MODELS[model]

    @property
    def _base_url(self):
        return 'http://{}'.format(self.host)

    def session_active(self):
        """Check if session is active."""
        url = self._base_url + self._model_info['url_session_active']
        try:
            response = requests.get(url, timeout=4)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return False

        title = self._model_info['regex_login'].findall(response.text)
        if title:
            _LOGGER.debug('found login title, session not active')
            return False

        return True

    def login(self):
        """Login to Ubee Admin interface."""
        url = self._base_url + self._model_info['url_login']
        payload = {
            'loginUsername': self.username,
            'loginPassword': self.password
        }
        try:
            response = requests.post(url, data=payload, timeout=4)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return False

        title = self._model_info['regex_login'].findall(response.text)
        if title:
            _LOGGER.error("Logging into the router failed. "
                          "Check username and password.")
            return False

        if response.status_code == 200:
            return True

        return False

    def logout(self):
        """Logout from Admin interface"""
        url = self._base_url + self._model_info['url_logout']
        try:
            response = requests.get(url, timeout=4)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return False

        if response.status_code == 200:
            return True

        return False

    def get_connected_devices(self):
        """Get list of connected devices"""
        lan_devices = self.get_connected_devices_lan()
        _LOGGER.debug('LAN devices: %s', lan_devices)
        wifi_devices = self.get_connected_devices_wifi()
        _LOGGER.debug('WIFI devices: %s', wifi_devices)
        devices = lan_devices.copy()
        devices.update(wifi_devices)
        return devices

    def _format_mac_address(self, address):
        """Format a given address to a default format."""
        # remove all ':' and '-'
        bare = address.upper().replace(':', '').replace('-', '')
        return ':'.join(bare[i:i + 2] for i in range(0, 12, 2))

    def get_connected_devices_lan(self):
        """Get list of connected devices via ethernet."""
        url = self._base_url + self._model_info['url_connected_devices_lan']
        try:
            response = requests.get(url, timeout=4)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return []

        data = response.text
        entries = self._model_info['regex_lan_devices'].findall(data)
        return {
            self._format_mac_address(address): ip
            for address, ip in entries
        }

    def get_connected_devices_wifi(self):
        """Get list of connected devices via wifi."""
        url = self._base_url + self._model_info['url_connected_devices_wifi']
        try:
            response = requests.get(url, timeout=4)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return []

        data = response.text
        entries = self._model_info['regex_wifi_devices'].findall(data)
        return {
            self._format_mac_address(address): hostname
            for address, hostname in entries
        }
