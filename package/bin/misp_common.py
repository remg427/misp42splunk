# coding=utf-8
import json
import re
import ssl
import time
import urllib3
import splunklib.client
import splunklib.data

__license__ = "LGPLv3"
__version__ = "6.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


class LimitChecker:
    """
    Centralised limit management for MISP commands.
    Checks response size and execution time limits.
    """

    def __init__(self, max_size_mb=None, max_time_sec=None, enable_logging=True, log_interval=10, logger=None):
        """
        Initialise the limit manager.

        Args:
            max_size_mb: Maximum cumulative size in MB (None = no limit)
            max_time_sec: Maximum time in seconds (None = no limit)
            enable_logging: Enable detailed logging
            log_interval: Progress logging interval (seconds)
            logger: Logger for diagnostic messages
        """
        self.max_size_bytes = max_size_mb * 1024 * 1024 if max_size_mb else None
        self.max_time_sec = max_time_sec
        self.logger = logger
        self.enable_logging = enable_logging
        self.log_interval = log_interval

        # Counters
        self.total_bytes_received = 0
        self.start_time = time.time()
        self.page_count = 0
        self.last_check_time = self.start_time

        # Statistics
        self.stats = {
            'pages_fetched': 0,
            'total_size_mb': 0.0,
            'elapsed_time_sec': 0.0,
            'stopped_by_size_limit': False,
            'stopped_by_time_limit': False,
            'average_page_size_kb': 0.0,
            'estimated_pages_remaining': 0
        }

        if self.enable_logging:
            self._log_info(
                f"LimitChecker initialized: max_size={max_size_mb}MB, "
                f"max_time={max_time_sec}s, log_interval={log_interval}s"
            )

    def add_response_size(self, response_size_bytes):
        """
        Record the size of a received response.

        Args:
            response_size_bytes: Response size in bytes
        """
        self.total_bytes_received += response_size_bytes
        self.page_count += 1
        self.stats['pages_fetched'] = self.page_count
        self.stats['total_size_mb'] = self.total_bytes_received / (1024 * 1024)

        # Average size per page
        if self.page_count > 0:
            avg_kb = (self.total_bytes_received / 1024) / self.page_count
            self.stats['average_page_size_kb'] = avg_kb

            # Estimatie count of pages before the max size limit is reached
            if self.max_size_bytes:
                remaining_bytes = self.max_size_bytes - self.total_bytes_received
                if avg_kb > 0:
                    self.stats['estimated_pages_remaining'] = int(remaining_bytes / (avg_kb * 1024))

        if self.enable_logging:
            self._log_debug(
                f"Page {self.page_count}: received {response_size_bytes / 1024:.2f}KB, "
                f"total {self.stats['total_size_mb']:.2f}MB, "
                f"avg {self.stats['average_page_size_kb']:.2f}KB/page"
            )

    def should_continue(self):
        """
        Check if execution should continue based on configured limits.

        Returns:
            tuple: (bool, str) - (should continue, stop reason if False)
        """
        current_time = time.time()
        elapsed = current_time - self.start_time
        self.stats['elapsed_time_sec'] = elapsed

        # Check size limit
        if (self.max_size_bytes and self.total_bytes_received >= self.max_size_bytes):
            self.stats['stopped_by_size_limit'] = True
            reason = (
                f"Size limit reached: {self.stats['total_size_mb']:.2f}MB "
                f"(limit: {self.max_size_bytes / (1024 * 1024):.2f}MB) "
                f"after {self.page_count} pages"
            )
            self._log_warning(reason)
            return False, reason

        # Check time limit
        if self.max_time_sec and elapsed >= self.max_time_sec:
            self.stats['stopped_by_time_limit'] = True
            reason = (
                f"Time limit reached: {elapsed:.2f}s "
                f"(limit: {self.max_time_sec}s) "
                f"after {self.page_count} pages, "
                f"{self.stats['total_size_mb']:.2f}MB"
            )
            self._log_warning(reason)
            return False, reason

        # Periodic progress logging
        if (self.enable_logging and (current_time - self.last_check_time >= self.log_interval)):
            time_remaining = ""
            if self.max_time_sec:
                time_remaining = (
                    f", {self.max_time_sec - elapsed:.0f}s remaining"
                )

            size_remaining = ""
            if self.max_size_bytes:
                remaining_mb = (
                    (self.max_size_bytes - self.total_bytes_received) /
                    (1024 * 1024)
                )
                size_remaining = f", {remaining_mb:.2f}MB remaining"

            self._log_info(
                f"Progress: {self.page_count} pages, "
                f"{self.stats['total_size_mb']:.2f}MB, "
                f"{elapsed:.2f}s elapsed"
                f"{time_remaining}{size_remaining}"
            )
            self.last_check_time = current_time

        return True, None

    def get_stats(self):
        """Return execution statistics."""
        return self.stats.copy()

    def log_final_stats(self):
        """Log final statistics."""
        if self.enable_logging:
            self._log_info(
                f"Execution completed: "
                f"{self.stats['pages_fetched']} pages, "
                f"{self.stats['total_size_mb']:.2f}MB, "
                f"{self.stats['elapsed_time_sec']:.2f}s, "
                f"avg {self.stats['average_page_size_kb']:.2f}KB/page"
            )

            if self.stats['stopped_by_size_limit']:
                self._log_warning("Stopped due to size limit")
            if self.stats['stopped_by_time_limit']:
                self._log_warning("Stopped due to time limit")

    def _log_info(self, message):
        if self.logger:
            self.logger.info(f"[LimitChecker] {message}")

    def _log_debug(self, message):
        if self.logger:
            self.logger.debug(f"[LimitChecker] {message}")

    def _log_warning(self, message):
        if self.logger:
            self.logger.warning(f"[LimitChecker] {message}")


def create_limit_checker(settings, logger=None):
    """
    Create a LimitChecker instance based on global configuration.

    Args:
        service: Splunk service
        logger: Optional logger

    Returns:
        LimitChecker: Configured limit manager instance
    """

    # If a limit is 0, disable it (None)
    max_size = (settings['max_response_size_mb'] if settings.get('max_response_size_mb', 0) > 0 else None)
    max_time = (settings['max_execution_time_sec'] if settings.get('max_execution_time_sec', 0) > 0 else None)

    return LimitChecker(
        max_size_mb=max_size,
        max_time_sec=max_time,
        enable_logging=settings['enable_limit_logging'],
        log_interval=settings['progress_log_interval'],
        logger=logger
    )


def logging_level(service, app_name):
    try:
        conf = service.confs[f"{app_name}_settings"]["logging"]
        level = conf.get("loglevel", "ERROR")
        if level in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            return level
    except Exception:
        pass
    return "ERROR"


def prepare_config(
    helper,
    app_name,
    misp_instance,
    storage_passwords,
    session_key=None,
):
    """
    Prepare and validate runtime configuration for a MISP instance.

    Splunk Cloud hardened:
    - No filesystem access
    - No direct .conf file reads
    - No environment variable assumptions
    - Defensive error handling
    - No secret leakage in logs
    """

    # ------------------------------------------------------------------
    # Defaults
    # ------------------------------------------------------------------

    config = {
        "misp_key": None,
        "misp_url": None,
        "host": None,
        "proxy_url": None,
        "proxy_username": None,
        "proxy_password": None,
        "misp_verifycert": False,
        "prefix": "misp_",
        "connection_timeout": 3,
        "read_timeout": 200,
        "max_response_size_mb": 100,
        "max_execution_time_sec": 300,
        "enable_limit_logging": True,
        "progress_log_interval": 10,
    }

    # ------------------------------------------------------------------
    # Helper parsers (PEP8 compliant)
    # ------------------------------------------------------------------

    def to_int(value, default):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def to_bool(value, default=False):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        if isinstance(value, int):
            return value == 1
        return default

    # ------------------------------------------------------------------
    # Obtain Splunk service
    # ------------------------------------------------------------------

    try:
        service = (
            helper.service
            if session_key is None
            else splunklib.client.connect(token=session_key)
        )
    except Exception as exc:
        raise RuntimeError(
            f"[MC-PC-E00] Unable to obtain Splunk service: {exc}"
        ) from exc

    # ------------------------------------------------------------------
    # Load global settings (Cloud-safe via REST)
    # ------------------------------------------------------------------

    try:
        global_conf = service.confs[
            "misp42splunk_settings"
        ]["global_settings"]

        config["max_response_size_mb"] = to_int(
            global_conf.get("max_response_size_mb"),
            config["max_response_size_mb"],
        )

        config["max_execution_time_sec"] = to_int(
            global_conf.get("max_execution_time_sec"),
            config["max_execution_time_sec"],
        )

        config["progress_log_interval"] = to_int(
            global_conf.get("progress_log_interval"),
            config["progress_log_interval"],
        )

        config["enable_limit_logging"] = to_bool(
            global_conf.get("enable_limit_logging"),
            config["enable_limit_logging"],
        )

        helper.log_debug(
            "[MC-PC-D00] Global settings successfully loaded"
        )

    except Exception as exc:
        helper.log_info(
            "[MC-PC-D01] Global settings not available; "
            "defaults will be used"
        )
        helper.log_debug(f"[MC-PC-D01-DETAIL] {exc}")

    # ------------------------------------------------------------------
    # Retrieve MISP instance via REST
    # ------------------------------------------------------------------

    response = service.get("misp42splunk_instances")

    if response.status != 200:
        raise RuntimeError(
            f"[MC-PC-E01] Failed to retrieve instances "
            f"(HTTP {response.status})"
        )

    data = splunklib.data.load(response.body.read())
    entries = data["feed"].get("entry", [])

    if isinstance(entries, dict):
        entries = [entries]

    app_config = None

    for entry in entries:
        if entry.get("title") == misp_instance:
            app_config = entry.get("content")
            break

    if not app_config:
        raise RuntimeError(
            f"[MC-PC-E02] MISP instance not found: {misp_instance}"
        )

    # ------------------------------------------------------------------
    # Validate MISP URL
    # ------------------------------------------------------------------

    misp_url = str(app_config.get("misp_url", "")).rstrip("/")

    if not misp_url.startswith("https://"):
        raise RuntimeError(
            "[MC-PC-E03] misp_url must begin with https://"
        )

    config["misp_url"] = misp_url

    match = re.search(r"(?:https?://)?([^:/ ]+)", misp_url)
    config["host"] = match.group(1) if match else misp_url

    # ------------------------------------------------------------------
    # TLS / certificate handling (Cloud safe)
    # ------------------------------------------------------------------

    config["misp_verifycert"] = to_bool(
        app_config.get("misp_verifycert")
    )

    if app_config.get("misp_ca_full_path"):
        config["misp_ca_cert"] = app_config.get(
            "misp_ca_full_path"
        )

    # Client certificates are generally not permitted in Splunk Cloud
    if to_bool(app_config.get("client_use_cert")):
        raise RuntimeError(
            "[MC-PC-E04] Client certificates are not "
            "supported in Splunk Cloud"
        )

    # ------------------------------------------------------------------
    # Basic instance settings
    # ------------------------------------------------------------------

    config["prefix"] = app_config.get(
        "prefix",
        config["prefix"],
    )

    config["connection_timeout"] = to_int(
        app_config.get("connection_timeout"),
        config["connection_timeout"],
    )

    config["read_timeout"] = to_int(
        app_config.get("read_timeout"),
        config["read_timeout"],
    )

    # ------------------------------------------------------------------
    # Retrieve stored credentials (secure)
    # ------------------------------------------------------------------

    # Splunk UCC stores credentials with double backticks as separator
    misp_instance_index = (
        f"{misp_instance}``splunk_cred_sep``"
    )

    for credential in storage_passwords:
        username = credential.content.get("username", "")
        clear_password = credential.content.get("clear_password")

        if misp_instance_index in username:
            try:
                creds = json.loads(clear_password)
                config["misp_key"] = str(
                    creds.get("misp_key")
                )
            except Exception:
                continue

    if not config["misp_key"]:
        raise RuntimeError(
            f"[MC-PC-E05] MISP API key not found for "
            f"instance {misp_instance}"
        )

    # ------------------------------------------------------------------
    # Proxy configuration (Cloud compliant via conf)
    # ------------------------------------------------------------------

    if to_bool(app_config.get("misp_use_proxy")):

        try:
            proxy_conf = service.confs[
                f"{app_name}_settings"
            ]["proxy"]

            hostname = proxy_conf.get("proxy_hostname")
            port = proxy_conf.get("proxy_port")

            if hostname and port:
                config["proxy_url"] = (
                    f"http://{hostname}:{port}"
                )

        except Exception:
            helper.log_info(
                "[MC-PC-D02] Proxy enabled but not configured"
            )

    helper.log_debug(
        "[MC-PC-D99] Configuration prepared successfully "
        "(Splunk Cloud hardened)"
    )

    return config


def make_list(helper, field):
    temp_v = []
    temp_v.append(field)
    return temp_v


def splunk_timestamp(input_ts):
    if isinstance(input_ts, list):
        output_ts = int(min(input_ts))
    elif isinstance(input_ts, str):
        output_ts = int(input_ts)
    elif not isinstance(input_ts, int):
        output_ts = int(time.time())
    else:
        output_ts = input_ts
    return output_ts


def normalise_data(key, value):
    normalised_data = []
    if isinstance(value, (str,int,float)):
        normalised_data.append((key, value))
    if isinstance(value, list):
        for item in value:
            normalised_data.extend(normalise_data(key, item))
    if isinstance(value, dict):
        for k, v in value.items():
            normalised_data.extend(normalise_data(k, v))
    return normalised_data


def generate_record(data, event_time=None, generator=None):
    if event_time is None:
        event_time = time.time()
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'))

    data_dict = dict()
    record = normalise_data('none', data)
    for key, val in record:
        val = str(val)
        key = str(key)
        if key in data_dict:
            if isinstance(data_dict[key], list):
                data_dict[key].append(val)
            else:
                data_dict[key] = [data_dict[key], val]
        else:
            data_dict[key] = val

    data_dict['_time'] = event_time
    data_dict['_raw'] = encoder.encode(data)

    if generator:
        return generator.gen_record(**data_dict)
    return data_dict


def misp_url_request(
    url_connection,
    method,
    url,
    body,
    headers,
    connection_timeout=3,
    read_timeout=200
):
    if method == "GET":
        r = url_connection.request(
            'GET',
            url,
            headers=headers,
            fields=body,
            timeout=urllib3.Timeout(
                connect=connection_timeout, read=read_timeout
            )
        )
    elif method == 'POST':
        encoded_body = json.dumps(body).encode('utf-8')
        r = url_connection.request(
            'POST',
            url,
            headers=headers,
            body=encoded_body,
            timeout=urllib3.Timeout(
                connect=connection_timeout, read=read_timeout
            )
        )
    elif method == "DELETE":
        encoded_body = json.dumps(body).encode('utf-8')
        r = url_connection.request(
            'DELETE',
            url,
            headers=headers,
            body=encoded_body,
            timeout=urllib3.Timeout(
                connect=connection_timeout, read=read_timeout
            )
        )
    elif method == "PUT":
        encoded_body = json.dumps(body).encode('utf-8')
        r = url_connection.request(
            'PUT',
            url,
            headers=headers,
            body=encoded_body,
            timeout=urllib3.Timeout(
                connect=connection_timeout, read=read_timeout
            )
        )
    else:
        raise Exception(
            f"No valid method {method} provided (GET/POST/PUT/DELETE)."
        )
    return r


def urllib_init_pool(helper, config):

    if config.get("misp_verifycert", True):
        cert_reqs = ssl.CERT_REQUIRED
    else:
        cert_reqs = ssl.CERT_NONE

    retries = urllib3.Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE"],
    )

    pool_kwargs = {
        "cert_reqs": cert_reqs,
        "retries": retries,
        "num_pools": 2,
        "maxsize": 2
    }

    proxy_url = config.get("proxy_url")
    connection = None

    try:
        if proxy_url:
            username = config.get("proxy_username")
            password = config.get("proxy_password")

            if username and password:
                proxy_headers = urllib3.make_headers(
                    proxy_basic_auth=f"{username}:{password}"
                )
                connection = urllib3.ProxyManager(
                    proxy_url,
                    proxy_headers=proxy_headers,
                    **pool_kwargs
                )
            else:
                connection = urllib3.ProxyManager(
                    proxy_url,
                    **pool_kwargs
                )
            return (
                connection,
                {
                    '_time': time.time(),
                    "_raw": "[MC401] Proxy Pool initialised successfully"
                }
            )
        else:
            connection = urllib3.PoolManager(**pool_kwargs)

            return (
                connection,
                {
                    '_time': time.time(),
                    "_raw": "[MC402] Pool initialised successfully"
                }
            )

    except Exception as exc:
        helper.log_error(f"[MC403] Pool initialisation failed: {exc}")
        return (
            connection,
            {'_time': time.time(), '_raw': f"[MC401] DEBUG ProxyManager failed {exc}"}
        )


def urllib_request(helper, url_connection, method, misp_url, body, config):
    # Set proper headers
    headers = {'Content-type': 'application/json'}
    headers['Authorization'] = config['misp_key']
    headers['Accept'] = 'application/json'
    connection_timeout = config.get('connection_timeout', 5)
    read_timeout = config.get('read_timeout', 60)
    response_size = 0
    try:
        r = misp_url_request(
            url_connection,
            method,
            misp_url,
            body,
            headers,
            connection_timeout,
            read_timeout
        )
        if r.status in (200, 201, 204):
            helper.log_info(
                f"[MC501] {method} request is successful. HTTP status={r.status}")
            if r.data:
                data = json.loads(r.data.decode('utf-8'))
                response_size = len(r.data)
            else:
                data = {}
        else:
            helper.log_error(
                f"[MC502] {method} request failed. HTTP status={r.status}")
            data = {
                '_time': time.time(),
                '_raw': (f"[MC502] ERROR {method} request failed. HTTP status={r.status}")
            }
    except Exception as exc:  # failed to execute request
        data = {
            '_time': time.time(),
            '_raw': (f"[MC503] {method} request failed {exc}")
        }

    return data, response_size


def get_attributes(helper, connection, config, body_dict,
                   limit_checker=None):
    """
    Fetch attributes from MISP with optional limit checking.

    Args:
        helper: Splunk helper object
        connection: urllib3 connection pool
        config: Configuration dict from prepare_config()
        body_dict: MISP API request body
        limit_checker: Optional LimitChecker instance

    Returns:
        list: List of attributes
    """
    response = []
    response_count = 0

    body_dict['includeSightings'] = config['include_sightings']

    if config['page'] == 0 and config['limit'] != 0:
        request_loop = True
        body_dict['limit'] = config['limit']
        body_dict['page'] = 1

        while request_loop:
            # Check limits before requesting next page
            if limit_checker:
                should_continue, stop_reason = (limit_checker.should_continue())
                if not should_continue:
                    helper.log_warning(f'[MC-603] Pagination stopped: {stop_reason}')
                    break

            response_size = 0
            iter_response, response_size = urllib_request(
                helper,
                connection,
                'POST',
                config['misp_url'],
                body_dict,
                config
            )

            # Record response size if limit checker is active
            if limit_checker:
                limit_checker.add_response_size(response_size)

            if 'response' in iter_response:
                if 'Attribute' in iter_response['response']:
                    rlength = len(
                        iter_response['response']['Attribute']
                    )
                    if rlength != 0:
                        attr_list = (
                            iter_response['response']['Attribute']
                        )
                        for attribute in attr_list:
                            response.append(dict(attribute))
                        helper.log_debug(
                            f"[MC-601] request on page {body_dict['page']} returned {rlength}")
                        body_dict['page'] = body_dict['page'] + 1
                        response_count += rlength
                    else:
                        helper.log_debug(
                            f"[MC-601] request on page {body_dict['page']} returned {rlength}")
                        # Last page is reached
                        request_loop = False
                else:
                    request_loop = False
            else:
                request_loop = False

    else:
        body_dict['limit'] = config['limit']
        body_dict['page'] = config['page']
        response_size = 0
        iter_response, response_size = urllib_request(
            helper,
            connection,
            'POST',
            config['misp_url'],
            body_dict,
            config
        )

        # Record response size if limit checker is active
        if limit_checker:
            limit_checker.add_response_size(response_size)

        if 'response' in iter_response:
            if 'Attribute' in iter_response['response']:
                for attribute in (
                    iter_response['response']['Attribute']
                ):
                    response.append(dict(attribute))
                rlength = len(
                    iter_response['response']['Attribute']
                )

    helper.log_info(
        f'[MC-602] response contains {rlength} records'
    )

    # Log final statistics if limit checker is active
    if limit_checker:
        limit_checker.log_final_stats()

    return response


def map_sighting_table(helper, sightings, config):
    """
    {
       Organisation: {
         id: 1
         name: MIRESEC
         uuid: 305d4e1e-80d2-4592-a1d7-b9cec29bb626
       }
       attribute_id: 17886
       attribute_uuid: 669748aa-e70c-4b48-892e-4b2a82a233fa
       date_sighting: 1734503055
       event_id: 57
       id: 13
       org_id: 1
       source:
       type: 0
       uuid: 3f0d52f8-ed19-4284-8455-a2afe6526b29
    }
    """
    prefix = config.get('prefix', "misp_")
    sighting_metric_dict = dict()

    try:
        for s in sightings:
            s_type = s.get('type', None)
            s_timestamp = int(s.get('date_sighting', None))
            s_source = s.get('source', None)
            s_org_name = None
            s_org_uuid = None
            if 'Organisation' in s:
                s_org_name = s['Organisation'].get('name', None)
                s_org_uuid = s['Organisation'].get('uuid', None)

            s_key = prefix + "sight_t" + str(s_type)
            if f'{s_key}_count' in sighting_metric_dict:
                sighting_metric_dict[f'{s_key}_count'] += 1
            else:
                sighting_metric_dict[f'{s_key}_count'] = 1

            if sighting_metric_dict.get(
                f'{s_key}_first_sight', 9999999999
            ) > s_timestamp:
                sighting_metric_dict[f'{s_key}_first_sight'] = s_timestamp
                sighting_metric_dict[f'{s_key}_first_org_name'] = s_org_name
                sighting_metric_dict[f'{s_key}_first_org_uuid'] = s_org_uuid
                sighting_metric_dict[f'{s_key}_first_source'] = s_source

            if sighting_metric_dict.get(
                f'{s_key}_last_sight', 1
            ) < s_timestamp:
                sighting_metric_dict[f'{s_key}_last_sight'] = s_timestamp
                sighting_metric_dict[f'{s_key}_last_org_name'] = s_org_name
                sighting_metric_dict[f'{s_key}_last_org_uuid'] = s_org_uuid
                sighting_metric_dict[f'{s_key}_last_source'] = s_source
    except Exception as exc:
        helper.log_debug(f"Sighting parse issue: {exc}")

    return sighting_metric_dict


def map_attribute_table(helper, attributes, config):
    attribute_mapping = {
        'category': 'category',
        'comment': 'comment',
        'deleted': 'deleted',
        'distribution': 'attribute_distribution',
        'event_id': 'event_id',
        'event_uuid': 'event_uuid',
        'first_seen': 'first_seen',
        'id': 'attribute_id',
        'last_seen': 'last_seen',
        'object_id': 'object_id',
        'object_relation': 'object_relation',
        'sharing_group_id': 'sharing_group_id',
        'timestamp': 'timestamp',
        'to_ids': 'to_ids',
        'type': 'type',
        'uuid': 'attribute_uuid',
        'value': 'value',
    }

    result_list = []
    misp_type_list = []

    expand_object = config.get('expand_object', False)
    host = config.get('host', "unknown_host")
    include_sightings = config.get('include_sightings', True)
    pipesplit = config.get('pipesplit', True)
    prefix = config.get('prefix', "misp_")

    for a in attributes:
        attribute = dict()
        for key, value in attribute_mapping.items():
            if key in a:
                attribute[f'{prefix}{value}'] = a[key]
        if 'Event' in a:
            e = a['Event']
            event_mapping = {
                # Existing (legacy) mappings
                'distribution': 'event_distribution',
                'id': 'event_id',
                'info': 'event_info',
                'org_id': 'org_id',
                'orgc_id': 'orgc_id',
                'publish_timestamp': 'publish_timestamp',
                'uuid': 'event_uuid',
                # New MISP 2.5 scalar fields
                'user_id': 'user_id',
                'threat_level_id': 'threat_level_id',
                'analysis': 'analysis',
                'date': 'event_date',
                'timestamp': 'event_timestamp',
                'first_publication': 'first_publication',
            }
            for key, value in event_mapping.items():
                if key in e:
                    attribute[f'{prefix}{value}'] = e[key]

            # Org nested object flattening (Requirements 2.1, 2.2, 2.3, 7.1, 7.5)
            # Overrides flat org_id from event_mapping when Org dict is present
            if isinstance(e.get('Org'), dict) and e['Org']:
                org = e['Org']
                if 'id' in org:
                    attribute[f'{prefix}org_id'] = org['id']
                if 'name' in org:
                    attribute[f'{prefix}org_name'] = org['name']
                if 'uuid' in org:
                    attribute[f'{prefix}org_uuid'] = org['uuid']

            # Orgc nested object flattening (Requirements 3.1, 3.2, 3.3, 7.2, 7.5)
            # Overrides flat orgc_id from event_mapping when Orgc dict is present
            if isinstance(e.get('Orgc'), dict) and e['Orgc']:
                orgc = e['Orgc']
                if 'id' in orgc:
                    attribute[f'{prefix}orgc_id'] = orgc['id']
                if 'name' in orgc:
                    attribute[f'{prefix}orgc_name'] = orgc['name']
                if 'uuid' in orgc:
                    attribute[f'{prefix}orgc_uuid'] = orgc['uuid']

            # ThreatLevel nested object flattening (Requirements 4.1, 4.2, 4.3, 4.4, 7.3, 7.5)
            # Overrides flat threat_level_id from event_mapping when ThreatLevel dict is present
            if isinstance(e.get('ThreatLevel'), dict) and e['ThreatLevel']:
                threat_level = e['ThreatLevel']
                if 'id' in threat_level:
                    attribute[f'{prefix}threat_level_id'] = threat_level['id']
                if threat_level.get('name'):
                    attribute[f'{prefix}threat_level_name'] = threat_level['name']

        if include_sightings and 'Sighting' in a:
            attribute.update(
                map_sighting_table(
                    helper, list(a.pop('Sighting')), config
                )
            )

        attribute[f'{prefix}host'] = host
        # Tag extraction (Requirements 6.1–6.5):
        # - Handles list of dicts, single dict, None/missing Tag
        # - Strips whitespace, preserves galaxy-style names unchanged
        # - Skips entries with missing/null/non-string name values
        attribute[f'{prefix}tag'] = []
        tag_value = a.pop('Tag', None)
        if isinstance(tag_value, list):
            for tag in tag_value:
                tag_name = tag.get('name')
                if isinstance(tag_name, str):
                    attribute[f'{prefix}tag'].append(tag_name.strip())
        elif isinstance(tag_value, dict):
            tag_name = tag_value.get('name')
            if isinstance(tag_name, str):
                attribute[f'{prefix}tag'].append(tag_name.strip())
        ts_key = f'{prefix}timestamp'
        if ts_key in attribute:
            attribute[ts_key] = int(attribute[ts_key])

        # Convert event_timestamp to int (Requirements 1.5, 5.4)
        event_ts_key = f'{prefix}event_timestamp'
        if event_ts_key in attribute:
            try:
                attribute[event_ts_key] = int(attribute[event_ts_key])
            except (ValueError, TypeError):
                pass  # Keep as string if conversion fails

        # Convert publish_timestamp to int (existing behavior, Requirement 5.4)
        pub_ts_key = f'{prefix}publish_timestamp'
        if pub_ts_key in attribute:
            try:
                attribute[pub_ts_key] = int(attribute[pub_ts_key])
            except (ValueError, TypeError):
                pass  # Keep as string if conversion fails

        # Combined: not part of an object
        # AND multivalue attribute AND to be split
        if (
            int(a.get('object_id', 0)) == 0
            and '|' in a['type']
            and pipesplit is True
        ):
            mv_type_list = str(a['type']).split('|')
            mv_value_list = str(a['value']).split('|')
            left_v = attribute.copy()
            left_v[f'{prefix}type'] = str(mv_type_list.pop())
            left_v[f'{prefix}value'] = str(mv_value_list.pop())
            result_list.append(left_v)
            if left_v[f'{prefix}type'] not in misp_type_list:
                misp_type_list.append(left_v[f'{prefix}type'])
            right_v = attribute.copy()
            right_v[f'{prefix}type'] = str(mv_type_list.pop())
            right_v[f'{prefix}value'] = str(mv_value_list.pop())
            result_list.append(right_v)
            if right_v[f'{prefix}type'] not in misp_type_list:
                misp_type_list.append(right_v[f'{prefix}type'])
        else:
            result_list.append(attribute)
            if attribute[f'{prefix}type'] not in misp_type_list:
                misp_type_list.append(attribute[f'{prefix}type'])
    del attributes
    helper.log_info(json.dumps(misp_type_list))

    # Consolidate attribute values under output table
    output_dict = dict()
    for r in result_list:
        if (
            expand_object is False
            and int(r[f'{prefix}object_id']) != 0
        ):
            r_key = (
                str(r[f'{prefix}event_id'])
                + '_object_'
                + str(r[f'{prefix}object_id'])
            )
        else:
            r_key = (
                str(r[f'{prefix}event_id'])
                + '_'
                + str(r[f'{prefix}attribute_id'])
            )

        if r_key not in output_dict:
            for t in misp_type_list:
                misp_t = prefix + t.replace('-', '_').replace('|', '_p_')
                if t == r[f'{prefix}type']:
                    r[misp_t] = str(r[f'{prefix}value'])
            output_dict[r_key] = r
        else:
            v = output_dict[r_key]
            if v[f'{prefix}object_id'] == 0:  # composed attribute
                misp_t = prefix + r[f'{prefix}type'].replace(
                    '-', '_'
                ).replace('|', '_p_')
                if misp_t in v:
                    if not isinstance(v[misp_t], list):
                        v[misp_t] = make_list(helper, v[misp_t])
                    v[misp_t].append(str(r[f'{prefix}value']))
                else:
                    v[misp_t] = str(r[f'{prefix}value'])
                v[f'{prefix}type'] = str(
                    r[f'{prefix}type'].replace('_', '-')
                    + '|'
                    + v[f'{prefix}type'].replace('_', '-')
                )
                v[f'{prefix}value'] = str(
                    r[f'{prefix}value'] + '|' + v[f'{prefix}value']
                )
            else:  # object to merge
                misp_t = prefix + r[f'{prefix}type'].replace('-', '_')
                if misp_t in v:
                    if not isinstance(v[misp_t], list):
                        v[misp_t] = make_list(helper, v[misp_t])
                    v[misp_t].append(r[f'{prefix}value'])
                else:
                    v[misp_t] = str(r[f'{prefix}value'])
                for orig_key, misp_key in attribute_mapping.items():
                    misp_key = prefix + misp_key
                    if misp_key in r:
                        if misp_key in v:
                            if not isinstance(v[misp_key], list):
                                v[misp_key] = make_list(
                                    helper, v[misp_key]
                                )
                            if r[misp_key] not in v[misp_key]:
                                v[misp_key].append(r[misp_key])
                        else:
                            v[misp_key] = r[misp_key]

                tag_list = v[f'{prefix}tag']
                for tag in r[f'{prefix}tag']:
                    if tag not in tag_list:
                        tag_list.append(tag)
                v[f'{prefix}tag'] = tag_list

            output_dict[r_key] = v

    return list(output_dict.values())


def get_events(helper, connection, config, body_dict,
               limit_checker=None):
    """
    Fetch events from MISP with optional limit checking.

    Args:
        helper: Splunk helper object
        connection: urllib3 connection pool
        config: Configuration dict from prepare_config()
        body_dict: MISP API request body
        limit_checker: Optional LimitChecker instance

    Returns:
        list: List of events
    """
    response = []
    response_count = 0

    body_dict['includeSightingdb'] = config['include_sightings']

    if config['page'] == 0 and config['limit'] != 0:
        request_loop = True
        body_dict['limit'] = config['limit']
        body_dict['page'] = 1

        while request_loop:
            # Check limits before requesting next page
            if limit_checker:
                should_continue, stop_reason = (
                    limit_checker.should_continue()
                )
                if not should_continue:
                    helper.log_warning(
                        f'[MC-803] Pagination stopped: {stop_reason}'
                    )
                    break

            response_size = 0
            iter_response, response_size = urllib_request(
                helper,
                connection,
                'POST',
                config['misp_url'],
                body_dict,
                config
            )

            # Record response size if limit checker is active
            if limit_checker:
                limit_checker.add_response_size(response_size)

            if 'response' in iter_response:
                rlength = len(iter_response['response'])
                if rlength != 0:
                    for r_item in iter_response['response']:
                        event = r_item.get('Event') or {}
                        if config['getioc'] is False:
                            event.pop('Attribute', None)
                            event.pop('Object', None)
                        if config['keep_galaxy'] is False:
                            event.pop('Galaxy', None)
                        if config['keep_related'] is False:
                            event.pop('RelatedEvent', None)
                        response.append(event)
                    helper.log_debug(
                        f"[MC-801] request on page {body_dict['page']} "
                        f"returned {rlength} event(s); querying next page"
                    )
                    body_dict['page'] = body_dict['page'] + 1
                    response_count += rlength
                else:
                    helper.log_debug(
                        f"[MC-801] request on page {body_dict['page']} returned {rlength}"
                    )
                    # Last page is reached
                    request_loop = False
            else:
                request_loop = False

    else:
        body_dict['limit'] = config['limit']
        body_dict['page'] = config['page']
        response_size = 0
        iter_response, response_size = urllib_request(
            helper,
            connection,
            'POST',
            config['misp_url'],
            body_dict,
            config
        )

        # Record response size if limit checker is active
        if limit_checker:
            limit_checker.add_response_size(response_size)

        if 'response' in iter_response:
            for r_item in iter_response['response']:
                event = r_item.get('Event') or {}
                if config['getioc'] is False:
                    event.pop('Attribute', None)
                    event.pop('Object', None)
                if config['keep_galaxy'] is False:
                    event.pop('Galaxy', None)
                if config['keep_related'] is False:
                    event.pop('RelatedEvent', None)
                response.append(event)
            response_count = len(iter_response['response'])

    helper.log_info(
        f"[MC-802] response contains {response_count} records"
    )

    # Log final statistics if limit checker is active
    if limit_checker:
        limit_checker.log_final_stats()

    return response


def flatten_object(d, parent_key='', sep='_'):
    items = []
    if isinstance(d, dict):
        for k, v in d.items():
            new_key = (
                f"{parent_key}{sep}{k.lower()}" if parent_key else k
            )
            if isinstance(v, dict):
                items.extend(
                    flatten_object(v, new_key, sep=sep).items()
                )
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    items.extend(
                        flatten_object(
                            {f"{new_key}{sep}{i}": item}, '', sep=sep
                        ).items()
                    )
            else:
                items.append((new_key, v))
    elif isinstance(d, list):
        for i, item in enumerate(d):
            items.extend(
                flatten_object(
                    {f"{parent_key}{sep}{i}": item}, '', sep=sep
                ).items()
            )
    return dict(items)


def map_event_table(helper, events, config):
    # Build output table and list of types
    result_list = []
    attribute_limit = int(config.get('attribute_limit', 0))
    host = config.get('host', "unknown_host")
    prefix = config.get('prefix', "misp_")
    # Process events and return a list of dict
    # if getioc=true each event entry contains a key Attribute
    # with a list of all attributes
    event_mapping = {
        'analysis': 'analysis',
        'attribute_count': 'analysis_count',
        'date': 'event_date',
        'disable_correlation': 'disable_correlation',
        'distribution': 'distribution',
        'extends_uuid': 'extends_uuid',
        'id': 'event_id',
        'info': 'event_info',
        'locked': 'locked',
        'proposal_email_lock': 'proposal_email_lock',
        'publish_timestamp': 'publish_timestamp',
        'published': 'event_published',
        'sharing_group_id': 'sharing_group_id',
        'threat_level_id': 'threat_level_id',
        'timestamp': 'event_timestamp',
        'uuid': 'event_uuid',
        'value': 'value',
    }
    for e in events:
        event_dict = dict()
        for key, value in event_mapping.items():
            if key in e:
                event_dict[f'{prefix}{value}'] = e[key]
        event_org = e.get('Org') or {}
        for org_key, org_value in event_org.items():
            event_dict[f'{prefix}org_{org_key}'] = org_value
        event_orgc = e.get('Orgc') or {}
        for orgc_key, orgc_value in event_orgc.items():
            event_dict[f'{prefix}orgc_{orgc_key}'] = orgc_value

        if e.get('Galaxy'):
            event_dict[f'{prefix}galaxy'] = flatten_object(
                e.pop('Galaxy'), f'{prefix}galaxy'
            )

        if e.get('RelatedEvent'):
            event_dict[f'{prefix}related'] = flatten_object(
                e.pop('RelatedEvent'), f'{prefix}related'
            )

        event_dict[f'{prefix}host'] = host
        event_dict[f'{prefix}tag'] = []
        tag_value = e.pop('Tag', None)
        if isinstance(tag_value, list):
            for tag in tag_value:
                tag_name = tag.get('name')
                if isinstance(tag_name, str):
                    event_dict[f'{prefix}tag'].append(tag_name.strip())
        elif isinstance(tag_value, dict):
            tag_name = tag_value.get('name')
            if isinstance(tag_name, str):
                event_dict[f'{prefix}tag'].append(tag_name.strip())

        if 'Object' in e:
            for o in e['Object']:
                object_dict = dict()
                for o_key, o_value in o.items():
                    object_dict[f'{prefix}object_{o_key}'] = o_value
                object_dict.pop(f'{prefix}object_Attribute')
                object_dict.pop(f'{prefix}object_event_id')
                attributes = o.pop('Attribute', None)
                if attributes:
                    attribute_list = map_attribute_table(
                        helper, attributes, config
                    )
                    if attribute_list:
                        if (
                            attribute_limit > 0
                            and attribute_limit < len(attribute_list)
                        ):
                            temp = attribute_list.copy()
                            attribute_list = temp[:attribute_limit]
                            helper.log_info(
                                f"[MC-901] object attribute count is {len(attribute_list)} "
                                f"'(was {len(temp)} truncated to {attribute_limit}"
                            )
                        for a in attribute_list:
                            a.update(object_dict)
                            a.update(event_dict)
                            result_list.append(a)
        if 'Attribute' in e:
            attributes = e.pop('Attribute', None)
            if attributes:
                attribute_list = map_attribute_table(
                    helper, attributes, config
                )
                if attribute_list:
                    if (
                        attribute_limit > 0
                        and attribute_limit < len(attribute_list)
                    ):
                        temp = attribute_list.copy()
                        attribute_list = temp[:attribute_limit]
                        helper.log_info(
                            f"[MC-902] attribute count is {len(attribute_list)} "
                            f"(was {len(temp)} truncated to {attribute_limit})"
                        )
                for a in attribute_list:
                    a.update(event_dict)
                    result_list.append(a)
        if config['getioc'] is False:
            event_dict[f'{prefix}timestamp'] = (
                event_dict[f'{prefix}event_timestamp']
            )
            result_list.append(event_dict)

    return result_list
