from builtins import str
from builtins import range
from builtins import object
import time
import traceback
import six
import munch

from cloudconnectlib.common import util
from cloudconnectlib.common.log import get_cc_logger
from cloudconnectlib.core import defaults
from cloudconnectlib.core.exceptions import HTTPError
from httplib2 import Http, socks, ProxyInfo
from solnlib.packages.requests import PreparedRequest, utils
from solnlib.utils import is_true

try: # Python2 environment support
    from httplib2 import SSLHandshakeError
except: # Python3 environment support
    from ssl import SSLError as SSLHandshakeError

_logger = get_cc_logger()

_PROXY_TYPE_MAP = {
    'http': socks.PROXY_TYPE_HTTP,
    'http_no_tunnel': socks.PROXY_TYPE_HTTP_NO_TUNNEL,
    'socks4': socks.PROXY_TYPE_SOCKS4,
    'socks5': socks.PROXY_TYPE_SOCKS5,
}


class HTTPResponse(object):
    """
    HTTPResponse class wraps response of HTTP request for later use.
    """

    def __init__(self, response, content):
        """Construct a HTTPResponse from response and content returned
        with httplib2 request"""
        self._status_code = response.status
        self._header = response
        self._body = self._decode_content(response, content)

    @staticmethod
    def _decode_content(response, content):
        if not content:
            return ''

        charset = utils.get_encoding_from_headers(response)

        if charset is None:
            charset = defaults.charset
            _logger.info(
                'Unable to find charset in response headers,'
                ' set it to default "%s"', charset
            )

        _logger.info('Decoding response content with charset=%s', charset)

        try:
            return content.decode(charset, errors='replace')
        except Exception as ex:
            _logger.warning(
                'Failure decoding response content with charset=%s,'
                ' decode it with utf-8: %s',
                charset, ex
            )

        return content.decode('utf-8', errors='replace')

    @property
    def header(self):
        return self._header

    @property
    def body(self):
        """
        Return response body as a `string`.
        :return: A `string`
        """
        return self._body

    @property
    def status_code(self):
        """
        Return response status code.
        :return: A `integer`
        """
        return self._status_code


def _make_prepare_url_func():
    """Expose prepare_url in `PreparedRequest`"""
    pr = PreparedRequest()

    def prepare_url(url, params=None):
        """Prepare the given HTTP URL with ability provided in requests lib.
        For some illegal characters in URL or parameters like space(' ') will
        be escaped to make sure we can request the correct URL."""
        pr.prepare_url(url, params=params)
        return pr.url

    return prepare_url


def get_proxy_info(proxy_config):
    if not proxy_config or not is_true(proxy_config.get('proxy_enabled')):
        _logger.info('Proxy is not enabled')
        return None

    url = proxy_config.get('proxy_url')
    port = proxy_config.get('proxy_port')

    if url or port:
        if not url:
            raise ValueError('Proxy "url" must not be empty')
        if not util.is_valid_port(port):
            raise ValueError(
                'Proxy "port" must be in range [1,65535]: %s' % port
            )

    user = proxy_config.get('proxy_username')
    password = proxy_config.get('proxy_password')

    if not all((user, password)):
        _logger.info('Proxy has no credentials found')
        user, password = None, None

    proxy_type = proxy_config.get('proxy_type')
    proxy_type = proxy_type.lower() if proxy_type else 'http'

    if proxy_type in _PROXY_TYPE_MAP:
        ptv = _PROXY_TYPE_MAP[proxy_type]
    elif proxy_type in list(_PROXY_TYPE_MAP.values()):
        ptv = proxy_type
    else:
        ptv = socks.PROXY_TYPE_HTTP
        _logger.info('Proxy type not found, set to "HTTP"')

    rdns = is_true(proxy_config.get('proxy_rdns'))

    proxy_info = ProxyInfo(
        proxy_host=url,
        proxy_port=int(port),
        proxy_type=ptv,
        proxy_user=user,
        proxy_pass=password,
        proxy_rdns=rdns
    )
    return proxy_info

def standardize_proxy_config(proxy_config):
    """
        This function is used to standardize the proxy information structure to get it evaluated through `get_proxy_info` function
    """

    if not isinstance(proxy_config, dict):
        raise ValueError("Received unexpected format of proxy configuration. Expected format: object, Actual format: {}".format(type(proxy_config)))

    standard_proxy_config = {
        "proxy_enabled": proxy_config.get("enabled", proxy_config.get("proxy_enabled")),
        "proxy_username": proxy_config.get("username", proxy_config.get("proxy_username")),
        "proxy_password": proxy_config.get("password", proxy_config.get("proxy_password")),
        "proxy_url": proxy_config.get("host", proxy_config.get("proxy_url")),
        "proxy_type": proxy_config.get("type", proxy_config.get("proxy_type")),
        "proxy_port": proxy_config.get("port", proxy_config.get("proxy_port")),
        "proxy_rdns": proxy_config.get("rdns", proxy_config.get("proxy_rdns"))
    }

    return standard_proxy_config


class HttpClient(object):
    def __init__(self, proxy_info=None):
        """Constructs a `HTTPRequest` with a optional proxy setting.
        """
        self._connection = None
    
        if proxy_info:
            if isinstance(proxy_info, munch.Munch):
                proxy_info = dict(proxy_info)

            # Updating the proxy_info object to make it compatible for getting evaluated through `get_proxy_info` function
            proxy_info = standardize_proxy_config(proxy_info)
            self._proxy_info = get_proxy_info(proxy_info)
        else:
            self._proxy_info = proxy_info
        self._url_preparer = PreparedRequest()

    def _send_internal(self, uri, method, headers=None, body=None, proxy_info=None):
        """Do send request to target URL and validate SSL cert by default.
        If validation failed, disable it and try again."""
        try:
            return self._connection.request(
                uri, body=body, method=method, headers=headers
            )
        except SSLHandshakeError:
            _logger.warning(
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verification failed. "
                "The certificate of the https server [%s] is not trusted, "
                "this add-on will proceed to connect with this certificate. "
                "You may need to check the certificate and "
                "refer to the documentation and add it to the trust list. %s",
                uri,
                traceback.format_exc()
            )

            self._connection = self._build_http_connection(
                proxy_info=proxy_info,
                disable_ssl_cert_validation=True
            )
            return self._connection.request(
                uri, body=body, method=method, headers=headers
            )

    def _retry_send_request_if_needed(self, uri, method='GET', headers=None, body=None):
        """Invokes request and auto retry with an exponential backoff
        if the response status is configured in defaults.retry_statuses."""
        retries = max(defaults.retries, 0)
        _logger.info('Invoking request to [%s] using [%s] method', uri, method)
        for i in range(retries + 1):
            try:
                response, content = self._send_internal(
                    uri=uri, body=body, method=method, headers=headers
                )
            except Exception as err:
                _logger.exception(
                    'Could not send request url=%s method=%s', uri, method)
                raise HTTPError('HTTP Error %s' % str(err))

            status = response.status

            if self._is_need_retry(status, i, retries):
                delay = 2 ** i
                _logger.warning(
                    'The response status=%s of request which url=%s and'
                    ' method=%s. Retry after %s seconds.',
                    status, uri, method, delay,
                )
                time.sleep(delay)
                continue

            return HTTPResponse(response, content)

    def _prepare_url(self, url, params=None):
        self._url_preparer.prepare_url(url, params)
        return self._url_preparer.url

    def _initialize_connection(self):
        if self._proxy_info:
            _logger.info('Proxy is enabled for http connection.')
        else:
            _logger.info('Proxy is not enabled for http connection.')
        self._connection = self._build_http_connection(self._proxy_info)

    def send(self, request):
        if not request:
            raise ValueError('The request is none')
        if request.body and not isinstance(request.body, six.string_types):
            raise TypeError('Invalid request body type: {}'.format(request.body))

        if self._connection is None:
            self._initialize_connection()

        try:
            url = self._prepare_url(request.url)
        except Exception:
            _logger.warning(
                'Failed to encode url=%s: %s',
                request.url, traceback.format_exc()
            )
            url = request.url

        return self._retry_send_request_if_needed(
            url, request.method, request.headers, request.body
        )

    @staticmethod
    def _build_http_connection(
            proxy_info=None,
            timeout=defaults.timeout,
            disable_ssl_cert_validation=defaults.disable_ssl_cert_validation):
        return Http(
            proxy_info=proxy_info,
            timeout=timeout,
            disable_ssl_certificate_validation=disable_ssl_cert_validation)

    @staticmethod
    def _is_need_retry(status, retried, maximum_retries):
        return retried < maximum_retries \
               and status in defaults.retry_statuses
