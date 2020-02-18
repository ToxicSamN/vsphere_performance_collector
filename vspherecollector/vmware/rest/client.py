
import requests
import urllib3
import json
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3.util.retry import Retry
from requests.exceptions import ConnectionError, ConnectTimeout, SSLError
from vspherecollector.vmware.rest.exceptions import SessionAuthenticationException, VcenterServiceUnavailable


BASE_URL = 'https://{}/rest/appliance/'
CIM_URL = 'https://{}/rest/com/vmware/cis/session'


class ApplianceAPI:

    def __init__(self, vcenter):
        self.base_url = BASE_URL.format(vcenter)


class SessionRetry:

    def __init__(self, session, retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )

        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        self.session = session
        self.response = None

    def get(self):
        return self.session


class CimSession(requests.Session):

    def __init__(self, vcenter, username, password, ssl_verify=True, ignore_weak_ssl=False):
        self._session_url = CIM_URL.format(vcenter)
        self.vcenter = vcenter
        self.response = None
        self.response_data = None
        super().__init__()
        self.auth = HTTPBasicAuth(username=username, password=password)
        self.verify = ssl_verify
        self._setup()

        if ignore_weak_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _setup(self):
        return SessionRetry(session=self).get()

    def response_json_to_dict(self):
        self.response_data = json.loads(self.response_data.decode('utf8'))

    def login(self):
        try:
            response = self.post(self._session_url)
            self.headers.update(
                {'vmware-api-session-id': json.loads(response.content.decode('utf8'))['value']})
            return self
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                # unauthenticated
                raise SessionAuthenticationException("Credentials not authorized")
            if e.response.status_code == 503:
                # Vcenter service offline
                raise VcenterServiceUnavailable("vCenter Service Unavailable")

    def logout(self):
        response = self.delete(self._session_url)

    def get(self, url, **kwargs):
        r"""Sends a GET request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault('allow_redirects', True)
        self.response = self.request('GET', url, **kwargs)
        self.response_data = self.response.content
        self.response_json_to_dict()

        # raise an exception if something went wrong
        self.response.raise_for_status()
        return self.response

    def options(self, url, **kwargs):
        r"""Sends a OPTIONS request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault('allow_redirects', True)
        self.response = self.request('OPTIONS', url, **kwargs)
        return self.response

    def head(self, url, **kwargs):
        r"""Sends a HEAD request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault('allow_redirects', False)
        self.response = self.request('HEAD', url, **kwargs)
        return self.response

    def post(self, url, data=None, json=None, **kwargs):
        r"""Sends a POST request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param json: (optional) json to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        self.response = self.request('POST', url, data=data, json=json, **kwargs)
        self.response_data = self.response.content
        self.response_json_to_dict()

        # raise an exception if something went wrong
        self.response.raise_for_status()
        return self.response

    def put(self, url, data=None, **kwargs):
        r"""Sends a PUT request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        self.response = self.request('PUT', url, data=data, **kwargs)
        self.response_data = self.response.content
        self.response_json_to_dict()

        # raise an exception if something went wrong
        self.response.raise_for_status()
        return self.response

    def patch(self, url, data=None, **kwargs):
        r"""Sends a PATCH request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        self.response = self.request('PATCH', url, data=data, **kwargs)
        self.response_data = self.response.content
        self.response_json_to_dict()

        # raise an exception if something went wrong
        self.response.raise_for_status()
        return self.response

    def delete(self, url, **kwargs):
        r"""Sends a DELETE request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        self.response = self.request('DELETE', url, **kwargs)
        return self.response
