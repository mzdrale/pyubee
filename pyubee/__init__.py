"""Module to communicate with Ubee routers."""

import logging
import re

from abc import abstractmethod
import requests
from requests.exceptions import RequestException


_LOGGER = logging.getLogger(__name__)


class Authenticator:
    """
    Base class providing authentication logic.

    Every router with specific authentication logic, should extend this class
    and its abstract methods.
    """

    # pylint: disable=too-few-public-methods
    def __init__(self, base_url, model_info, http_get_handler, http_post_handler):
        """Create authenticator for router instance."""
        # to be overwritten in childclasses
        self.csrf_field_name = None
        self.base_url = base_url
        self.model_info = model_info
        self._get = http_get_handler
        self._post = http_post_handler

    def _get_csrf_token(self):
        if self.csrf_field_name is None:
            return None

        url = self.base_url + self.model_info['url_session_active']
        response = self._get(url)
        matches = re.findall(r'<input(.*?)name="' + self.csrf_field_name
                             + '" value="([a-zA-Z0-9]+)">', response.text)
        result = matches[0] if matches else None
        return result[1] if result else None

    @abstractmethod
    def _build_login_payload(self, login, password, csrf_token=None):
        pass

    def authenticate(self, url, username, password):
        """Authenticate with router."""
        referer_url = self.base_url + self.model_info['url_session_active']
        csrf_token = self._get_csrf_token()
        payload = self._build_login_payload(username, password, csrf_token)
        self._post(url, payload, referer_url)


class DefaultAuthenticator(Authenticator):
    """Default authenticator sending login and password via POST."""

    # pylint: disable=too-few-public-methods
    def _build_login_payload(self, login, password, csrf_token=None):
        return {
            'loginUsername': login,
            'loginPassword': password
        }


class Evw3226Authenticator(Authenticator):
    """EVW3226 authenticator - simulates real browser activity."""

    # pylint: disable=too-few-public-methods
    def __init__(self, *args, **kwargs):
        """Create EVW3226 authenticator with CSRF protection handling."""
        super().__init__(*args, **kwargs)
        self.csrf_field_name = 'ValidCode'

    def _build_login_payload(self, login, password, csrf_token=None):
        return {
            'LoginPassword': login + ',' + password,
            'LoginRetryPassword': '',
            'FourceLogOff': '',  # they have a typo in a form lol
            'ValidCode': csrf_token,
            'action': 'save',
            'gonext': '../login.htm',
            'myname': '../login.htm',
            self.csrf_field_name: csrf_token
        }

    def authenticate(self, url, username, password):
        """Authenticate with EVW3226 router."""
        super().authenticate(url, username, password)
        # it checks for consecutive requests to verify if you're a human,
        # so we have to simulate them
        self._get(self.base_url + '/main.htm',
                  referer=self.base_url + '/cgi-bin/setup.cgi')
        self._get(self.base_url + '/cgi-bin/setup.cgi?gonext=main2',
                  referer=self.base_url + '/main.htm')


MODEL_REGEX = re.compile(r'<modelName>(.*)</modelName>')

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
            r'<td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'  # mac address
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
        'authenticator': DefaultAuthenticator
    },
    'EVW320B': {
        'url_session_active': '/BasicStatus.asp',
        'url_login': '/goform/loginMR3',
        'url_logout': '/logout.asp',
        'url_connected_devices_lan': '/RgDhcp.asp',
        'url_connected_devices_wifi': '/wlanAccess.asp',
        'regex_login': re.compile(r'name="loginUsername"'),
        'regex_wifi_devices': re.compile(
            r'<tr bgcolor=#[0-9a-fA-F]+>'
            r'<td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'  # mac address
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
        'authenticator': DefaultAuthenticator
    },
    'EVW321B': {
        'url_session_active': '/HomePageMR4.asp',
        'url_login': '/goform/loginMR4',
        'url_logout': '/logout.asp',
        # includes all devices, also WiFi
        'url_connected_devices_lan': '/ConnectedDevicesMR4.asp',
        # there is no separate page with WiFi devices
        'url_connected_devices_wifi': None,
        'regex_login': re.compile(r'name="loginUsername"'),
        'regex_wifi_devices': None,
        'regex_lan_devices': re.compile(
            r'<td id="MACAddr">([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'  # mac address
            r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2})</td>'  # mac address, cont'd
            r'<td id="IPAddr">(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>'  # ip address
        ),
        'authenticator': DefaultAuthenticator
    },
    'EVW3226@UPC': {
        'url_session_active': '/cgi-bin/setup.cgi?gonext=login',
        'url_login': '/cgi-bin/setup.cgi',
        'url_logout': '/cgi-bin/setup.cgi?gonext=main2___20',
        # includes all devices, also WiFi
        'url_connected_devices_lan': '/cgi-bin/setup.cgi?gonext=RgBasicDHCPClientDevices',
        # there is no separate page with WiFi devices
        'url_connected_devices_wifi': None,
        'regex_login': re.compile(r'<div class="upc_loginform">'),
        'regex_wifi_devices': None,
        'regex_lan_devices': re.compile(
            r'<tr>\n    \t\t\t\t\t\t'
            r'<td>([0-9a-fA-F:]{17})</td>\n    \t\t\t\t\t\t'  # mac address
            r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>'  # ip address
        ),
        'authenticator': Evw3226Authenticator
    },
}

MODEL_ALIASES = {
    'EVW3200-Wifi': 'EVW320B'
}

SUPPORTED_MODELS = list(MODELS.keys()) + list(MODEL_ALIASES.keys())


class Ubee:
    """Represents a session to a Ubee Router."""

    def __init__(self, host=None, username=None, password=None, model='detect'):
        """Initialize a Ubee session."""
        self.host = host
        self.username = username
        self.password = password

        if model == 'detect':
            model = self.detect_model()
            _LOGGER.debug('Detected model: %s', model)

        if model in MODEL_ALIASES:
            model = MODEL_ALIASES.get(model)

        if model not in MODELS:
            _LOGGER.info('pyubee supported models: %s', ', '.join(SUPPORTED_MODELS))
            raise LookupError('Unknown model: ' + model)

        _LOGGER.debug('Using model: %s', model)

        self.model = model
        self._model_info = MODELS[model]
        self.authenticator = self._model_info['authenticator'](
            self._base_url, self._model_info, self._get, self._post)

    @property
    def _base_url(self):
        """Form base url."""
        return 'http://{}'.format(self.host)

    def _get(self, url, referer=None):
        """Do a HTTP GET."""
        # pylint: disable=no-self-use
        _LOGGER.debug('HTTP GET: %s', url)
        headers = {'Host': self.host}
        if referer is not None:
            headers['Referer'] = referer
        return requests.get(url, timeout=4, headers=headers)

    def _post(self, url, data, referer=None):
        """Do a HTTP POST."""
        # pylint: disable=no-self-use
        _LOGGER.debug('HTTP POST: %s, data: %s', url, data)
        headers = {'Host': self.host}
        if referer is not None:
            headers['Referer'] = referer
        return requests.post(url, data=data, timeout=4, headers=headers)

    def detect_model(self):
        """Autodetect Ubee model."""
        url = self._base_url + "/RootDevice.xml"
        try:
            response = self._get(url)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return "Unknown"

        data = response.text
        entries = MODEL_REGEX.findall(data)

        if entries:
            return entries[1]

        return "Unknown"

    def session_active(self):
        """Check if session is active."""
        url = self._base_url + self._model_info['url_session_active']
        try:
            response = self._get(url)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return False

        login_phrase = self._model_info['regex_login'].findall(response.text)
        if login_phrase:
            _LOGGER.debug('found login page, session not active')
            return False

        return True

    def login(self):
        """Login to Ubee Admin interface."""
        url = self._base_url + self._model_info['url_login']

        try:
            self.authenticator.authenticate(url, self.username, self.password)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return False

        # self.session_active() is only reliable method for verifying authentication on EWV3226
        return self.session_active()

    def logout(self):
        """Logout from Admin interface."""
        url = self._base_url + self._model_info['url_logout']
        try:
            response = self._get(url)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return False

        if response.status_code == 200:
            return True

        return False

    def get_connected_devices(self):
        """Get list of connected devices."""
        lan_devices = self.get_connected_devices_lan()
        _LOGGER.debug('LAN devices: %s', lan_devices)
        wifi_devices = self.get_connected_devices_wifi()
        _LOGGER.debug('WIFI devices: %s', wifi_devices)
        devices = lan_devices.copy()
        devices.update(wifi_devices)
        return devices

    def get_connected_devices_lan(self):
        """Get list of connected devices via ethernet."""
        url = self._base_url + self._model_info['url_connected_devices_lan']
        try:
            response = self._get(url)
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
        wifi_regexp = self._model_info['regex_wifi_devices']
        if wifi_regexp is None:
            _LOGGER.debug('No WiFi lookup support')
            return {}

        url = self._base_url + self._model_info['url_connected_devices_wifi']
        try:
            response = self._get(url)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return []

        data = response.text
        entries = wifi_regexp.findall(data)
        return {
            self._format_mac_address(address): hostname
            for address, hostname in entries
        }

    def _format_mac_address(self, address):
        """Format a given address to a default format."""
        # pylint: disable=no-self-use
        # remove all ':' and '-'
        bare = address.upper().replace(':', '').replace('-', '')
        return ':'.join(bare[i:i + 2] for i in range(0, 12, 2))
