"""Module to communicate with Ubee routers."""

import logging
import re
from abc import abstractmethod
from base64 import b64encode

import requests
from requests.auth import HTTPDigestAuth
from requests.exceptions import RequestException

import json


_LOGGER = logging.getLogger(__name__)
_LOGGER_TRAFFIC = logging.getLogger(__name__ + '.traffic')

HTTP_REQUEST_TIMEOUT = 4  # seconds


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
        self._post(url, payload, referer=referer_url)

    @property
    def headers(self):
        """Get authentication related headers, used for every request."""
        return {}


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


class BasicAccessAuthAuthenticator(Authenticator):
    """Basic Auth authenticator."""

    def __init__(self, base_url, model_info, http_get_handler, http_post_handler):
        """Create authenticator."""
        super().__init__(base_url, model_info, http_get_handler, http_post_handler)

        self._username = None
        self._password = None

    def _build_login_payload(self, login, password, csrf_token=None):
        return None

    def authenticate(self, url, username, password):
        """Store username/password for later use."""
        # Store username/password.
        self._username = username
        self._password = password

    @property
    def headers(self):
        """Get authentication related headers, used for every request."""
        headers = {}

        if self._username and self._password:
            user_pass = bytes(self._username + ':' + self._password, "utf-8")
            user_pass_b64 = b64encode(user_pass).decode('ascii')
            authorization = 'Basic %s' % user_pass_b64
            headers['authorization'] = authorization

        return headers

class DigestAuthAuthenticator(Authenticator):
    """Digest Auth authenticator."""

    def __init__(self, base_url, model_info, http_get_handler, http_post_handler):
        """Create authenticator."""
        super().__init__(base_url, model_info, http_get_handler, http_post_handler)

        self._username = None
        self._password = None

    def _build_login_payload(self, login, password, csrf_token=None):
        return None

    def authenticate(self, url, username, password):
        """Store username/password for later use."""
        # Store username/password.
        self._username = username
        self._password = password

    @property
    def headers(self):
        """Get authentication related headers, used for every request."""
        headers = {}

        return headers


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
            r'<td>(.*)</td>'  # hostname
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
        'authenticator': DefaultAuthenticator,
        'JSONList': False
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
        'authenticator': DefaultAuthenticator,
        'JSONList': False
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
            r'<td id="MACAddr">([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'  # mac address
            r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})</td>'  # mac address, cont'd
            r'<td id="IPAddr">(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>'  # ip address
        ),
        'authenticator': DefaultAuthenticator,
        'JSONList': False
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
        'authenticator': Evw3226Authenticator,
        'JSONList': False
    },
    'DVW32CB': {
        'url_session_active': '/main.asp',
        'url_login': '/RgSwInfo.asp',
        'url_logout': '/logout.asp',
        # includes all devices, also WiFi
        'url_connected_devices_lan': '/RgDhcp.asp',
        'url_connected_devices_wifi': '/wlanAccess.asp',
        'regex_login': re.compile(r'name="loginUsername"'),
        'regex_wifi_devices': re.compile(
            r'<tr bgcolor=#[0-9a-fA-F]+>'
            r'<td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'  # mac address
            r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2})</td>'  # mac address, cont'd
            r'<td>\d+</td>'  # age
            r'<td>.*</td>'  # rssi
            r'<td>.*</td>'  # ip address
            r'<td>(.*)</td>'  # hostname
            r'<td>.*</td>'  # mode
            r'<td>\d+</td>'  # speed
            r'</tr>'
        ),
        'regex_lan_devices': re.compile(
            r'<tr>\n    \t\t\t\t\t\t'
            r'<td>([0-9a-fA-F:]{17})</td>\n    \t\t\t\t\t\t'  # mac address
            r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>'  # ip address
        ),
        'authenticator': DefaultAuthenticator,
        'JSONList': False
    },
    'DDW36C': {
        'url_session_active': '/RgSwInfo.asp',
        'url_login': '/RgSwInfo.asp',
        'url_logout': '/logout.asp',
        'url_connected_devices_lan': '/RgDhcp.asp',
        'url_connected_devices_wifi': '/wlanAccess.asp',
        'regex_login': re.compile(r'name="loginUsername"'),
        'regex_wifi_devices': re.compile(
            r'<tr bgcolor=#[0-9a-fA-F]+>'
            r'<td>([0-9a-fA-F:]{17})</td>'  # mac address
            r'<td>.*</td>'  # age
            r'<td>.*</td>'  # rssi
            r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>'  # ip address
        ),
        'regex_lan_devices': re.compile(
            r'<tr bgcolor=#[0-9a-fA-F]+>'
            r'<td>([0-9a-fA-F:]{17})</td>'  # mac address
            r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>'  # ip address
        ),
        'authenticator': BasicAccessAuthAuthenticator,
        'JSONList': False
    },
    'UBC1303BA00': {
        'url_session_active': '/htdocs/cm_info_status.php',
        'url_login': '/htdocs/cm_info_status.php',
        'url_logout': '/htdocs/unauth.php',
        'url_connected_devices_lan': '/htdocs/rg_mgt_clientlist.php',
        # no URL for WiFi
        'url_connected_devices_wifi': None,
        'regex_login': re.compile(r'name="loginUsername"'),
        'regex_wifi_devices': None,
        'regex_lan_devices': r'\'{\"mgt_cpestatus_table\".*\'',
        'authenticator': DigestAuthAuthenticator,
        'JSONList': True
    },
}

MODEL_ALIASES = {
    'EVW3200-Wifi': 'EVW320B',
    'EVW32C-0S': 'EVW32C-0N',
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

        if model in MODEL_ALIASES:
            model = MODEL_ALIASES.get(model)

        if model not in MODELS:
            _LOGGER.info('pyubee supported models: %s', ', '.join(SUPPORTED_MODELS))
            raise LookupError('Unknown model: ' + model)

        self.model = model
        self._model_info = MODELS[model]
        self.authenticator = self._model_info['authenticator'](
            self._base_url, self._model_info, self._get, self._post)

    @property
    def _base_url(self):
        """Form base url."""
        return 'http://{}'.format(self.host)

    def _get(self, url, **headers):
        """Do a HTTP GET."""
        if hasattr(self, 'authenticator') and isinstance(self.authenticator, DigestAuthAuthenticator):
            # We are using digest auth:
            response = requests.get(url, timeout=HTTP_REQUEST_TIMEOUT, auth=HTTPDigestAuth(self.username, self.password))
            return response
        # Use the rudimentary auth
        # pylint: disable=no-self-use
        _LOGGER.debug('HTTP GET: %s', url)
        req_headers = {'Host': self.host}

        # Add custom headers.
        for key, value in headers.items():
            key_title = key.title()
            req_headers[key_title] = value

        # Add headers from authenticator.
        for key, value in self._authenticator_headers.items():
            key_title = key.title()
            req_headers[key_title] = value

        _LOGGER_TRAFFIC.debug('Sending request:')
        _LOGGER_TRAFFIC.debug('  HTTP GET %s', url)
        for key, value in req_headers.items():
            _LOGGER_TRAFFIC.debug('  Header: %s: %s', key, value)

        response = requests.get(url, timeout=HTTP_REQUEST_TIMEOUT, headers=req_headers)
        _LOGGER.debug('Response status code: %s', response.status_code)

        _LOGGER_TRAFFIC.debug('Received response:')
        _LOGGER_TRAFFIC.debug('  Status: %s, Reason: %s', response.status_code, response.reason)
        for key, value in response.headers.items():
            _LOGGER_TRAFFIC.debug('  Header: %s: %s', key, value)
        _LOGGER_TRAFFIC.debug('  Data: %s', repr(response.text))

        return response


    def _post(self, url, data, **headers):
        if hasattr(self, 'authenticator') and isinstance(self.authenticator, DigestAuthAuthenticator):
            # We are using digest auth:
            response = requests.post(url, data=data, timeout=HTTP_REQUEST_TIMEOUT, auth=HTTPDigestAuth(self.username, self.password))
            return response
        # Use the rudimentary auth
        """Do a HTTP POST."""
        # pylint: disable=no-self-use
        _LOGGER.debug('HTTP POST: %s, data: %s', url, repr(data))
        req_headers = {'Host': self.host}

        # Add custom headers.
        for key, value in headers.items():
            key_title = key.title()
            req_headers[key_title] = value

        # Add headers from authenticator.
        for key, value in self._authenticator_headers.items():
            key_title = key.title()
            req_headers[key_title] = value

        _LOGGER_TRAFFIC.debug('Sending request:')
        _LOGGER_TRAFFIC.debug('  HTTP POST %s', url)
        for key, value in req_headers.items():
            _LOGGER_TRAFFIC.debug('  Header: %s: %s', key, value)
        _LOGGER_TRAFFIC.debug('  Data: %s', repr(data))

        response = requests.post(url, data=data, timeout=HTTP_REQUEST_TIMEOUT, headers=req_headers)
        _LOGGER.debug('Response status code: %s', response.status_code)

        _LOGGER_TRAFFIC.debug('Received response:')
        _LOGGER_TRAFFIC.debug('  Status: %s, Reason: %s', response.status_code, response.reason)
        for key, value in response.headers.items():
            _LOGGER_TRAFFIC.debug('  Header: %s: %s', key, value)
        _LOGGER_TRAFFIC.debug('  Data: %s', repr(response.text))

        return response

    def detect_model(self):
        """Autodetect Ubee model."""
        _LOGGER.debug('Detecting model')

        url = self._base_url + "/RootDevice.xml"
        try:
            response = self._get(url)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return "Unknown. Some models cannot be automatically detected at the moment."

        data = response.text
        entries = MODEL_REGEX.findall(data)

        if entries:
            _LOGGER.debug('Detected model: %s', entries[1])
            return entries[1]

        _LOGGER.debug('Could not detect model')
        return "Unknown. Some models cannot be automatically detected at the moment."

    def session_active(self):
        """Check if session is active."""
        _LOGGER.debug('Checking if session is active')

        url = self._base_url + self._model_info['url_session_active']
        try:
            response = self._get(url)

            if response.status_code == 401:
                return False
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return False

        login_phrase = self._model_info['regex_login'].findall(response.text)
        if login_phrase:
            _LOGGER.debug('Found login page, session not active')
            return False

        _LOGGER.debug('Did not find login page, session active')
        return True

    def login(self):
        """Login to Ubee Admin interface."""
        _LOGGER.debug('Logging in')

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
        _LOGGER.debug('Logging out')

        url = self._base_url + self._model_info['url_logout']
        try:
            response = self._get(url)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return False

        if response.status_code == 200:
            _LOGGER.debug('Logged out')
            return True

        _LOGGER.debug('Unable to log out')
        return False

    def get_connected_devices(self):
        """Get list of connected devices."""
        lan_devices = self.get_connected_devices_lan()
        _LOGGER.debug('LAN devices: %s', lan_devices)
        wifi_devices = self.get_connected_devices_wifi()
        _LOGGER.debug('WIFI devices: %s', wifi_devices)
        devices = lan_devices.copy()
        devices.update(wifi_devices)
        if self._model_info['JSONList']:
            devices = {key:val for key, val in devices.items() if val.lower() != "unknown"}
        return devices

    def get_connected_devices_lan(self):
        """Get list of connected devices via ethernet."""
        _LOGGER.debug('Getting list of connected lan devices')

        url = self._base_url + self._model_info['url_connected_devices_lan']
        try:
            response = self._get(url)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return {}

        data = response.text
        if self._model_info['JSONList']:
            lan_regexp = self._model_info['regex_lan_devices']
            #data = data[1:-1]
            matches = re.search(lan_regexp, data, re.MULTILINE)
            match = matches.group()[1:-1]
            entries = json.loads(match)
            return {
                self._format_mac_address(entry["lan_dhcpinfo_mac_address"]): entry["lan_dhcpinfo_hostname"]
                for entry in entries["lan_dhcpinfo_table"]
            }
        entries = self._model_info['regex_lan_devices'].findall(data)
        return {
            self._format_mac_address(address): ip
            for address, ip in entries
        }

    def get_connected_devices_wifi(self):
        """Get list of connected devices via wifi."""
        _LOGGER.debug('Getting list of connected wifi devices')

        wifi_regexp = self._model_info['regex_wifi_devices']
        if wifi_regexp is None:
            _LOGGER.debug('No WiFi lookup support')
            return {}

        url = self._base_url + self._model_info['url_connected_devices_wifi']
        try:
            response = self._get(url)
        except RequestException as ex:
            _LOGGER.error("Connection to the router failed: %s", ex)
            return {}

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

    @property
    def _authenticator_headers(self):
        """Get headers from authenticator."""
        # work around no authenticator set when detecting model
        if not hasattr(self, 'authenticator'):
            return {}

        return self.authenticator.headers
