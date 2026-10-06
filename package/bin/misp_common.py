# coding=utf-8
import json
import logging
import re
import ssl
import time
import urllib3
import splunklib.client
import splunklib.data

# Absolute upper bound on pagination iterations. Acts as a last-resort guard
# against runaway/infinite pagination (e.g. a MISP endpoint that ignores the
# "page" parameter and keeps returning the same non-empty result set).
MAX_PAGINATION_PAGES = 100000

# Splunk's per-field size limit, and the size at which generate_record() cuts a
# value. Kept at module level so the truncation summary can quote it.
MAX_FIELD_SIZE = 2097152

# Last-resort bound on the number of records a command hands to Splunk, applied
# alongside the configurable max_output_size_mb. See OutputBudget for why a
# producer-side bound is required at all.
MAX_OUTPUT_ROWS = 1000000

# MISP restSearch response headers worth surfacing in search.log.
MISP_INFO_HEADERS = (
    'X-Result-Count',
    'X-Export-Module-Used',
    'X-Response-Format',
)


def _resolve_logger(helper):
    """
    Return the most appropriate logger for diagnostic messages.

    Prefers the per-command logger provided by the Splunk searchcommands
    framework (``helper.logger``, named after the command class and honouring
    the ``logging_level`` SPL option). Falls back to the root logger when the
    caller does not expose one.
    """
    logger = getattr(helper, "logger", None)
    if logger is not None:
        return logger
    return logging.getLogger()


def _log_request_failure(helper, iter_response, page, code):
    """
    Report a MISP reply that carries no "response" key.

    urllib_request() turns HTTP errors and transport exceptions into a dict
    holding a "_raw" description rather than raising, so without this the caller
    cannot tell an empty result set from a failed request. ERROR level keeps the
    reason visible at the default loglevel.
    """
    detail = iter_response.get('_raw', iter_response)
    helper.log_error(
        f'[{code}] request on page {page} returned no "response" key; '
        f'no further page will be fetched: {detail}'
    )

__license__ = "LGPLv3"
__version__ = "6.1.0"
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

    if max_size is None and max_time is None and logger is not None:
        # With both disabled only an empty page stops the loop. Callers that
        # buffer the whole result set also lose their only memory bound.
        logger.warning(
            '[LimitChecker] max_response_size_mb and max_execution_time_sec '
            'are both 0: pagination has no size or time backstop'
        )

    return LimitChecker(
        max_size_mb=max_size,
        max_time_sec=max_time,
        enable_logging=settings['enable_limit_logging'],
        log_interval=settings['progress_log_interval'],
        logger=logger
    )


class OutputBudget:
    """
    Bound on what a command hands to Splunk.

    splunklib's SCP v2 record writer cannot emit partial chunks:
    ``RecordWriterV2.flush()`` returns immediately for ``partial=True`` and
    ``_execute_chunk_v2()`` drains the whole generator before writing, so every
    record is buffered until generate()/stream() returns and ``maxresultrows``
    provides no back-pressure. Without a producer-side bound a search with large
    rows appears to hang, then runs out of memory.

    Peak memory is several times the figure counted here: ``write_chunk()``
    holds the buffer, a str copy and a bytes copy at once. Budget roughly a
    third of the memory the search process can afford.
    """

    def __init__(self, max_rows=None, max_size_mb=None, logger=None):
        self.max_rows = max_rows or MAX_OUTPUT_ROWS
        self.max_size_bytes = max_size_mb * 1024 * 1024 if max_size_mb else None
        self.logger = logger
        self.rows = 0
        self.bytes = 0
        self.exhausted = False
        self.stop_reason = None

    @staticmethod
    def _record_size(record):
        """
        Approximate what one record occupies in splunklib's buffer.

        The serialised row carries _raw *and* every individual field, so counting
        only _raw under-reports by roughly half.
        """
        total = 0
        for value in record.values():
            if isinstance(value, str):
                total += len(value)
            elif isinstance(value, (list, tuple)):
                total += sum(len(str(item)) for item in value)
            else:
                total += len(str(value))
        return total

    def consume(self, record):
        """
        Account for one emitted record.

        Returns True once the budget is spent, meaning the caller should stop
        producing. The record passed in has already been yielded: the boundary is
        checked after the fact so a record is never built and then dropped.
        """
        self.rows += 1
        try:
            self.bytes += self._record_size(record)
        except Exception:
            pass

        if self.max_size_bytes and self.bytes >= self.max_size_bytes:
            self.stop_reason = (
                f'output size limit reached: {self.bytes / (1024 * 1024):.2f}MB '
                f'(limit: {self.max_size_bytes / (1024 * 1024):.2f}MB) '
                f'after {self.rows} record(s)'
            )
        elif self.rows >= self.max_rows:
            self.stop_reason = (
                f'output row limit reached: {self.rows} record(s) '
                f'(limit: {self.max_rows})'
            )

        self.exhausted = self.stop_reason is not None
        return self.exhausted

    def log_summary(self, helper, code='MC-808', message=None):
        """Report truncation at ERROR; stay quiet when the budget held."""
        if not self.exhausted:
            if self.logger:
                self.logger.info(
                    f'[OutputBudget] {self.rows} record(s), '
                    f'{self.bytes / (1024 * 1024):.2f}MB handed to Splunk'
                )
            return
        helper.log_error(
            f'[{code}] Output stopped: {self.stop_reason}. Results are '
            'incomplete - narrow the search, or raise max_output_size_mb'
        )
        if message:
            message.add(f'INCOMPLETE - output stopped: {self.stop_reason}')


def create_output_budget(settings, logger=None):
    """Build an OutputBudget from the global settings (0 disables the size cap)."""
    max_size = (
        settings['max_output_size_mb']
        if settings.get('max_output_size_mb', 0) > 0
        else None
    )
    return OutputBudget(
        max_rows=MAX_OUTPUT_ROWS, max_size_mb=max_size, logger=logger
    )


def stanza_content(service, app_name, stanza_name):
    """
    Return a conf stanza as a plain dict of its keys.

    Always go through ``Entity.content`` rather than calling ``.get()`` on the
    stanza: ``splunklib.client.Stanza`` subclasses ``Entity``, whose ``get()`` is
    an HTTP GET on a sub-path, not a dict lookup, and raises on the resulting 404.
    """
    return dict(service.confs[f"{app_name}_settings"][stanza_name].content)


def logging_level(service, app_name):
    try:
        content = stanza_content(service, app_name, "logging")
        level = content.get("loglevel", "ERROR")
        if level in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            return level
    except Exception:
        pass
    return "ERROR"


def misp_bool(value, default=False):
    """
    Read a boolean out of a conf value or a json_request key.

    Both sources are untyped: a flag can arrive as a real bool, as 1/0, or as
    "true"/"yes"/"on". Anything unrecognised returns ``default``.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    if isinstance(value, int):
        return value == 1
    return default


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
        # Fallbacks used until Global Settings is saved; keep them aligned with
        # the defaultValue of each field in globalConfig.json.
        "max_response_size_mb": 512,
        "max_execution_time_sec": 900,
        # Peak memory at flush is about three times this figure (buffer + str
        # copy + bytes copy, see OutputBudget).
        "max_output_size_mb": 256,
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

    to_bool = misp_bool

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
        # stanza_content() returns the stanza's real key/value dict. Calling
        # .get() on the Stanza itself performs an HTTP GET and raises, which the
        # except branch below turned into "use the defaults" - the reason the
        # Global Settings tab never had any effect.
        global_conf = stanza_content(
            service, app_name, "global_settings"
        )

        config["max_response_size_mb"] = to_int(
            global_conf.get("max_response_size_mb"),
            config["max_response_size_mb"],
        )

        config["max_execution_time_sec"] = to_int(
            global_conf.get("max_execution_time_sec"),
            config["max_execution_time_sec"],
        )

        config["max_output_size_mb"] = to_int(
            global_conf.get("max_output_size_mb"),
            config["max_output_size_mb"],
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
        # ERROR, not INFO: falling back here means every value set in the
        # Global Settings tab is ignored, which silently changes the size and
        # time budgets the pagination loop enforces.
        helper.log_error(
            "[MC-PC-D01] Global settings could not be read; built-in defaults "
            f"will be used (max_response_size_mb="
            f"{config['max_response_size_mb']}, max_execution_time_sec="
            f"{config['max_execution_time_sec']}): {exc}"
        )

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

    match = re.search(r"(?:https://)?([^:/ ]+)", misp_url)
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


def _note_truncation(generator, key, original_size):
    """
    Record that one field value had to be cut to MAX_FIELD_SIZE.

    Counted rather than logged per occurrence, which would flood search.log. The
    first is reported at ERROR so the data loss is visible at the default
    loglevel; the rest are summarised by log_truncation_summary().
    """
    if generator is None:
        return
    stats = getattr(generator, '_misp_truncations', None)
    if stats is None:
        stats = {'count': 0, 'fields': {}, 'largest': 0}
        try:
            generator._misp_truncations = stats
        except Exception:
            return  # command object refuses attributes; skip accounting

    stats['count'] += 1
    stats['fields'][key] = stats['fields'].get(key, 0) + 1
    if original_size > stats['largest']:
        stats['largest'] = original_size

    if stats['count'] == 1 and hasattr(generator, 'log_error'):
        generator.log_error(
            f"[GR-003] value of '{key}' truncated from {original_size} to "
            f'{MAX_FIELD_SIZE} bytes: data is being lost. Further truncations '
            'are counted and reported once at the end of the search'
        )


def log_truncation_summary(generator, message=None):
    """Report the truncations accumulated by _note_truncation(), if any."""
    stats = getattr(generator, '_misp_truncations', None)
    if not stats or not stats.get('count'):
        return
    if message:
        message.add(
            f"{stats['count']} value(s) cut at {MAX_FIELD_SIZE} bytes"
        )
    top = ', '.join(
        f'{key}={count}'
        for key, count in sorted(
            stats['fields'].items(), key=lambda kv: kv[1], reverse=True
        )[:5]
    )
    if hasattr(generator, 'log_error'):
        generator.log_error(
            f"[GR-004] {stats['count']} value(s) truncated to "
            f"{MAX_FIELD_SIZE} bytes (largest original was "
            f"{stats['largest']} bytes); most affected: {top}. Those values are "
            'incomplete in the results'
        )


def generate_record(data, event_time=None, generator=None):
    if event_time is None:
        event_time = time.time()
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'))

    TRUNCATION_MARKER = "...[TRUNCATED: field exceeded 2MB limit]"

    data_dict = dict()
    record = normalise_data('none', data)
    for key, val in record:
        val = str(val)
        key = str(key)
        
        # Check and truncate oversized fields
        if len(val) > MAX_FIELD_SIZE:
            # Truncate to leave room for truncation marker
            original_size = len(val)
            truncate_at = MAX_FIELD_SIZE - len(TRUNCATION_MARKER) - 100
            val = val[:truncate_at] + TRUNCATION_MARKER
            _note_truncation(generator, key, original_size)


        if key in data_dict:
            if isinstance(data_dict[key], list):
                data_dict[key].append(val)
            else:
                data_dict[key] = [data_dict[key], val]
        else:
            data_dict[key] = val

    data_dict['_time'] = event_time
    
    # Also check _raw field size
    raw_data = encoder.encode(data)
    if len(raw_data) > MAX_FIELD_SIZE:
        original_size = len(raw_data)
        truncate_at = MAX_FIELD_SIZE - len(TRUNCATION_MARKER) - 100
        raw_data = raw_data[:truncate_at] + TRUNCATION_MARKER
        _note_truncation(generator, '_raw', original_size)
    data_dict['_raw'] = raw_data

    if generator:
        return generator.gen_record(**data_dict)
    return data_dict


def truncate_large_value(value, max_size=2097152):
    """
    Truncate large values to prevent exceeding Splunk field size limits.
    
    Args:
        value: The value to check and potentially truncate
        max_size: Maximum allowed size in bytes (default: 2MB)
    
    Returns:
        Truncated value if oversized, original value otherwise
    """
    if value is None:
        return value
    
    value_str = str(value)
    if len(value_str) > max_size:
        truncation_marker = "...[TRUNCATED: value exceeded 2MB limit]"
        truncate_at = max_size - len(truncation_marker) - 100
        return value_str[:truncate_at] + truncation_marker
    
    return value


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
        # urllib3 emits an InsecureRequestWarning per request when certificate
        # verification is off. Splunk's ChunkedExternProcessor labels everything a
        # search command writes to stderr as ERROR, so each one lands in
        # search.log as two spurious ERROR lines - the message and the
        # "warnings.warn(" source line. A 254-page search produced over 500 of
        # them, burying the real diagnostics. Say it once, then silence it.
        helper.log_warn(
            '[MC404] misp_verifycert is false for this instance: TLS '
            'certificates are NOT validated. Per-request urllib3 warnings are '
            'suppressed to keep search.log readable'
        )
        urllib3.disable_warnings(
            urllib3.exceptions.InsecureRequestWarning
        )

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


def _capture_response_headers(helper, response, headers_out=None):
    """
    Log the informative MISP response headers, and expose them to the caller.

    X-Result-Count is MISP's own count for the search, which is the only
    server-side number available to tell a complete answer from a truncated one.
    Whether it reports the page or the whole match set depends on the MISP
    version, so it is logged verbatim rather than interpreted.
    """
    try:
        headers = response.headers
    except Exception:
        return

    captured = {}
    for name in MISP_INFO_HEADERS:
        value = headers.get(name)
        if value is not None:
            captured[name] = value

    if headers_out is not None:
        headers_out.update(captured)

    if captured:
        helper.log_debug(
            '[MC504] MISP response headers: '
            + ', '.join(f'{key}={value}' for key, value in captured.items())
        )


def urllib_request(helper, url_connection, method, misp_url, body, config,
                   headers_out=None):
    """
    Perform one request against MISP.

    Args:
        headers_out: optional dict, filled with the MISP_INFO_HEADERS present on
            the response so the caller can report result counts.

    Returns:
        tuple: (decoded body or an error dict carrying "_raw", response size)
    """
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
        _capture_response_headers(helper, r, headers_out)
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


def misp_count(helper, connection, config, body_dict):
    """
    Ask MISP how many records a search matches, before fetching any of them.

    Issued once per search, before any page is fetched, so the log can state what
    fraction of the match set was retrieved.

    returnFormat=count walks the matching rows but serialises none of them and
    attaches no per-attribute context, so it is far cheaper than fetching them.
    The cost still scales with the match set and is charged against
    max_execution_time_sec.

    The scope matches what the fetch will do:
      - no page, or page 0: count the whole search, with limit=0 and no page
      - an explicit page: count that page, with the same limit and page

    Filters are sent verbatim. Both CountExport and JsonExport declare
    non_restrictive_export, so neither gets restSearch's to_ids/published
    defaults and nothing needs adding here.

    Returns:
        int, or None when no usable count came back.
    """
    probe = dict(body_dict)
    probe['returnFormat'] = 'count'
    if config.get('page'):
        probe['limit'] = config['limit']
        probe['page'] = config['page']
    else:
        probe['limit'] = 0
        probe.pop('page', None)

    headers_out = {}
    data, response_size = urllib_request(
        helper, connection, 'POST', config['misp_url'], probe, config,
        headers_out=headers_out
    )

    # The body is a bare number, so json.loads() yields an int. Fall back to the
    # X-Result-Count header, which the count export sets to the same value.
    count = None
    if isinstance(data, bool):
        pass
    elif isinstance(data, int):
        count = data
    elif isinstance(data, str) and data.strip().lstrip('-').isdigit():
        count = int(data.strip())
    if count is None:
        reported = headers_out.get('X-Result-Count')
        try:
            count = int(reported)
        except (TypeError, ValueError):
            count = None

    if count is None:
        detail = data.get('_raw', data) if isinstance(data, dict) else data
        helper.log_error(
            f'[MC-607] returnFormat=count returned no usable number, '
            f'continuing without a total: {detail}'
        )
    else:
        helper.log_info(
            f'[MC-608] MISP reports {count} record(s) matching this search '
            f'(returnFormat=count, {response_size} byte response)'
        )
    return count


def iter_attribute_pages(helper, connection, config, body_dict,
                         limit_checker=None, message=None):
    """
    Yield one list of attributes per MISP page.

    Nothing is kept across pages, so a consumer that writes each page onward
    keeps peak memory proportional to ``limit`` rather than to the whole result
    set. The result is single-pass; use get_attributes() when a list is needed.

    End-of-fetch reporting sits in a finally block because a generator may be
    abandoned before it is exhausted.

    Args:
        helper: Splunk helper object
        connection: urllib3 connection pool
        config: Configuration dict from prepare_config()
        body_dict: MISP API request body
        limit_checker: Optional LimitChecker instance
        message: Optional CommandMessage collecting the run status
    """
    response_count = 0
    reported_count = None

    if limit_checker is None:
        limit_checker = create_limit_checker(config, logger=_resolve_logger(helper))

    body_dict['includeSightings'] = config['include_sightings']

    # The per-page X-Result-Count is page-scoped here, so a count request is the
    # only way to know the total. It runs after the LimitChecker starts, so its
    # cost is charged against max_execution_time_sec.
    probe_total = misp_count(helper, connection, config, body_dict)
    if message:
        message.add(
            f'matched={probe_total}' if probe_total is not None
            else 'matched=unknown (count request failed)'
        )

    try:
        if config['page'] == 0 and config['limit'] != 0:
            request_loop = True
            body_dict['limit'] = config['limit']
            body_dict['page'] = 1

            while request_loop:
                # Guard against an endpoint that ignores "page"
                if body_dict['page'] > MAX_PAGINATION_PAGES:
                    helper.log_error(
                        f'[MC-604] Pagination stopped: reached hard page cap '
                        f'({MAX_PAGINATION_PAGES} pages)'
                    )
                    break

                # ERROR, not WARNING: stopping here truncates the result set and
                # must be visible at the default loglevel.
                if limit_checker:
                    should_continue, stop_reason = limit_checker.should_continue()
                    if not should_continue:
                        helper.log_error(
                            f'[MC-603] Pagination stopped after '
                            f'{response_count} attribute(s) on page '
                            f"{body_dict['page']}: {stop_reason}"
                        )
                        if message:
                            message.add(f'INCOMPLETE - fetch stopped after '
                                        f'{response_count}: {stop_reason}')
                        break

                page_headers = {}
                iter_response, response_size = urllib_request(
                    helper,
                    connection,
                    'POST',
                    config['misp_url'],
                    body_dict,
                    config,
                    headers_out=page_headers
                )
                reported_count = page_headers.get(
                    'X-Result-Count', reported_count
                )

                if limit_checker:
                    limit_checker.add_response_size(response_size)

                if 'response' in iter_response:
                    if 'Attribute' in iter_response['response']:
                        page = [
                            dict(attribute) for attribute
                            in iter_response['response']['Attribute']
                        ]
                        rlength = len(page)
                        helper.log_debug(
                            f"[MC-601] request on page {body_dict['page']} returned {rlength}")
                        if rlength != 0:
                            body_dict['page'] = body_dict['page'] + 1
                            response_count += rlength
                            yield page
                        else:
                            # Last page is reached
                            request_loop = False
                    else:
                        request_loop = False
                else:
                    _log_request_failure(
                        helper, iter_response, body_dict['page'], 'MC-605'
                    )
                    request_loop = False

        else:
            _apply_pagination(body_dict, config)
            page_headers = {}
            iter_response, response_size = urllib_request(
                helper,
                connection,
                'POST',
                config['misp_url'],
                body_dict,
                config,
                headers_out=page_headers
            )
            reported_count = page_headers.get('X-Result-Count', reported_count)

            if limit_checker:
                limit_checker.add_response_size(response_size)

            if 'response' in iter_response:
                if 'Attribute' in iter_response['response']:
                    page = [
                        dict(attribute) for attribute
                        in iter_response['response']['Attribute']
                    ]
                    response_count = len(page)
                    if page:
                        yield page
            else:
                _log_request_failure(
                    helper, iter_response, body_dict.get('page', 'n/a'),
                    'MC-606'
                )
    finally:
        if probe_total is not None:
            coverage = _coverage_suffix(response_count, probe_total,
                                        'count request')
        else:
            coverage = _coverage_suffix(response_count, reported_count)
        helper.log_info(
            f'[MC-602] response contains {response_count} records{coverage}'
        )

        if limit_checker:
            limit_checker.log_final_stats()


def get_attributes(helper, connection, config, body_dict,
                   limit_checker=None, message=None):
    """
    Fetch attributes from MISP as a single list.

    List form of iter_attribute_pages(): it materialises every page, so peak
    memory scales with the number of attributes fetched. Prefer
    iter_attribute_pages() where each page can be written onward as it arrives.

    Returns:
        list: List of attributes
    """
    return [
        attribute
        for page in iter_attribute_pages(
            helper, connection, config, body_dict, limit_checker, message
        )
        for attribute in page
    ]


def order_groups_by_event(body_dict):
    """
    True when the request order makes attributes of one event contiguous.

    Required by iter_attribute_table(): its carry-over window only works if the
    first sort key is event_id.
    """
    order = body_dict.get('order')
    if not order:
        return False
    if not isinstance(order, str):
        order = ','.join(str(rule) for rule in order)
    first = order.split(',')[0].strip().split(' ')[0]
    return first.lower().endswith('event_id')


def iter_attribute_table(helper, pages, config):
    """
    Map attribute pages to output rows, one page at a time.

    map_attribute_table() merges attributes sharing event_id+object_id, so a
    group split across a page boundary would yield two partial rows. With the
    results ordered by event_id an event's attributes are contiguous, so holding
    back the trailing event of each page and prepending it to the next keeps
    every group whole. Peak memory is one page plus one event.

    Requires an event_id-ordered request; see order_groups_by_event().
    """
    carry = []
    for page in pages:
        batch = carry + page
        carry = []
        if not batch:
            continue

        # Hold back the trailing event: more of it may arrive on the next page.
        last_event = batch[-1].get('event_id')
        split = len(batch)
        while split > 0 and batch[split - 1].get('event_id') == last_event:
            split -= 1
        if split == 0:
            # Whole batch is one event; keep accumulating.
            carry = batch
            continue
        carry = batch[split:]

        for row in map_attribute_table(helper, batch[:split], config):
            yield row

    if carry:
        for row in map_attribute_table(helper, carry, config):
            yield row


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
                # Truncate fields that could be large
                if key in ('value', 'comment'):
                    attribute[f'{prefix}{value}'] = truncate_large_value(a[key])
                else:
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
        # Two different kinds of collision share this dict, and the key says
        # which: attributes of one object group under the object, while the two
        # halves the pipesplit above produced share one attribute id. Decided
        # from r, whose ids are still scalars - the accumulated row may already
        # hold lists.
        is_object_group = (
            expand_object is False
            and int(r[f'{prefix}object_id']) != 0
        )
        if is_object_group:
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
            if not is_object_group:  # composed attribute
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


def _prune_event(event, config, discarded=None):
    """
    Drop the event structures the caller asked not to keep.

    Anything dropped here was still transferred and still counted against
    max_response_size_mb. Pass ``discarded`` (a dict) to accumulate how many bytes
    each key cost, which shows whether a request flag is worth setting
    (metadata / excludeGalaxy / includeEventCorrelations).
    """
    drop = []
    if config['getioc'] is False:
        drop.append('Attribute')
        drop.append('Object')
    if config['keep_galaxy'] is False:
        drop.append('Galaxy')
    if config['keep_related'] is False:
        drop.append('RelatedEvent')

    for key in drop:
        value = event.pop(key, None)
        if discarded is not None and value:
            try:
                discarded[key] = discarded.get(key, 0) + len(
                    json.dumps(value)
                )
            except (TypeError, ValueError):
                pass

    return event


class CommandMessage:
    """
    Per-run status line, stamped onto every record a command emits.

    Carries what the log says about totals and truncation into the result set as
    ``<prefix><command>_message``, so a partial answer is visible without opening
    search.log.

    The value is whatever is known when a record is emitted. Pages are streamed,
    so records emitted before a stop cannot mention it: the final records carry
    the most complete message. ``| stats values(...)`` shows every variant.
    """

    def __init__(self, field):
        self.field = field
        self.notes = []

    def add(self, note):
        if note and note not in self.notes:
            self.notes.append(note)

    def text(self):
        return '; '.join(self.notes) if self.notes else 'ok'

    def stamp(self, record):
        """Attach the message as it currently stands. Returns the record."""
        try:
            record[self.field] = self.text()
        except Exception:
            pass
        return record


def prefixed(config, name):
    """
    Name of an output field as the mappers build it: <prefix><name>.

    ``prefix`` is a user option, so a literal like 'misp_timestamp' only matches
    the default. Look field names up through here instead.
    """
    prefix = config.get('prefix') or 'misp_'
    return f'{prefix}{name}'


def message_field(config, command):
    """Name of the message field: <prefix><command>_message."""
    return prefixed(config, f'{command}_message')


def _apply_pagination(body_dict, config):
    """
    Put limit/page on the request, or take them off when pagination is disabled.

    ``limit`` is always stated, including 0, so the logged body reflects the limit
    in force.

    limit=0 means no pagination, so ``page`` is removed: MISP pages are 1-based
    and the key is meaningless once paging is off. A ``page`` left over from the
    caller's JSON body is dropped too.
    """
    body_dict['limit'] = config['limit']
    if config['limit'] == 0:
        body_dict.pop('page', None)
    else:
        body_dict['page'] = config['page']


def _coverage_suffix(fetched, total_value, source='X-Result-Count'):
    """
    Report the total MISP gave us, and a coverage ratio only when it means one.

    ``source`` names where the number came from; they are not interchangeable:

      X-Result-Count on /events/restSearch      the whole match set
      X-Result-Count on /attributes/restSearch  page-scoped, not a total
      count request                             a real total, via
                                                returnFormat=count

    A percentage is only derived when the value can plausibly be a total, which
    requires it to be at least what was already fetched.
    """
    if total_value is None:
        return ''
    try:
        total = int(total_value)
    except (TypeError, ValueError):
        return f'; MISP {source} reported {total_value}'
    if total <= 0 or fetched > total:
        return (
            f'; MISP {source} reported {total}, which cannot be a total for '
            'this search so no coverage is derived from it'
        )
    return (
        f'; MISP {source} reported {total} '
        f'({100.0 * fetched / total:.1f}% of it fetched)'
    )


def _discard_report(helper, discarded, limit_checker, code):
    """Log how much of the received payload was thrown away, biggest first."""
    if not discarded:
        return
    total = sum(discarded.values())
    parts = ', '.join(
        f'{key}={size / (1024 * 1024):.2f}MB'
        for key, size in sorted(
            discarded.items(), key=lambda kv: kv[1], reverse=True
        )
    )
    received = getattr(limit_checker, 'total_bytes_received', 0) or 0
    share = f'{100 * total / received:.1f}%' if received else 'n/a'
    helper.log_debug(
        f'[{code}] discarded {total / (1024 * 1024):.2f}MB of the '
        f'{received / (1024 * 1024):.2f}MB received ({share}): {parts}. '
        'Suppress these server-side to keep them off the wire.'
    )


def iter_event_pages(helper, connection, config, body_dict,
                     limit_checker=None, message=None):
    """
    Yield one list of pruned events per MISP page.

    Nothing is kept across pages, so a consumer that writes each page onward
    keeps peak memory proportional to ``limit`` rather than to the whole result
    set. This matters most with ``getioc=true``, where one event costs several
    MB. The result is single-pass; use get_events() when a list is needed.

    End-of-fetch reporting sits in a finally block because a generator may be
    abandoned before it is exhausted.

    Args:
        helper: Splunk helper object
        connection: urllib3 connection pool
        config: Configuration dict from prepare_config()
        body_dict: MISP API request body
        limit_checker: Optional LimitChecker instance
        message: Optional CommandMessage collecting the run status

    Yields:
        list: the events of one page, already pruned by _prune_event()
    """
    response_count = 0

    if limit_checker is None:
        limit_checker = create_limit_checker(config, logger=_resolve_logger(helper))

    body_dict['includeSightingdb'] = config['include_sightings']

    # Measuring the discarded payload costs a json.dumps() per dropped
    # structure per event, so only do it under DEBUG.
    discarded = None
    try:
        if _resolve_logger(helper).isEnabledFor(logging.DEBUG):
            discarded = {}
    except Exception:
        discarded = None

    # Last X-Result-Count seen, compared against the final tally.
    reported_count = None

    try:
        if config['page'] == 0 and config['limit'] != 0:
            request_loop = True
            body_dict['limit'] = config['limit']
            body_dict['page'] = 1

            while request_loop:
                # Guard against an endpoint that ignores "page"
                if body_dict['page'] > MAX_PAGINATION_PAGES:
                    helper.log_error(
                        f'[MC-804] Pagination stopped: reached hard page cap '
                        f'({MAX_PAGINATION_PAGES} pages)'
                    )
                    break

                # ERROR, not WARNING: stopping here truncates the result set and
                # must be visible at the default loglevel.
                if limit_checker:
                    should_continue, stop_reason = (
                        limit_checker.should_continue()
                    )
                    if not should_continue:
                        helper.log_error(
                            f'[MC-803] Pagination stopped after '
                            f"{response_count} event(s) on page "
                            f"{body_dict['page']}: {stop_reason}"
                        )
                        if message:
                            message.add(f'INCOMPLETE - fetch stopped after '
                                        f'{response_count}: {stop_reason}')
                        break

                page_headers = {}
                iter_response, response_size = urllib_request(
                    helper,
                    connection,
                    'POST',
                    config['misp_url'],
                    body_dict,
                    config,
                    headers_out=page_headers
                )
                reported_count = page_headers.get(
                    'X-Result-Count', reported_count
                )
                if message and reported_count is not None:
                    # On /events/restSearch this header is the real total, so no
                    # separate count request is needed.
                    message.add(f'matched={reported_count}')

                if limit_checker:
                    limit_checker.add_response_size(response_size)

                if 'response' in iter_response:
                    rlength = len(iter_response['response'])
                    if rlength != 0:
                        page = [
                            _prune_event(
                                r_item.get('Event') or {}, config, discarded
                            )
                            for r_item in iter_response['response']
                        ]
                        helper.log_debug(
                            f"[MC-801] request on page {body_dict['page']} "
                            f"returned {rlength} event(s); querying next page"
                        )
                        body_dict['page'] = body_dict['page'] + 1
                        response_count += rlength
                        yield page
                    else:
                        helper.log_debug(
                            f"[MC-801] request on page {body_dict['page']} returned {rlength}"
                        )
                        # Last page is reached
                        request_loop = False
                else:
                    _log_request_failure(
                        helper, iter_response, body_dict['page'], 'MC-805'
                    )
                    request_loop = False

        else:
            _apply_pagination(body_dict, config)
            page_headers = {}
            iter_response, response_size = urllib_request(
                helper,
                connection,
                'POST',
                config['misp_url'],
                body_dict,
                config,
                headers_out=page_headers
            )
            reported_count = page_headers.get('X-Result-Count', reported_count)

            if limit_checker:
                limit_checker.add_response_size(response_size)

            if 'response' in iter_response:
                page = [
                    _prune_event(r_item.get('Event') or {}, config, discarded)
                    for r_item in iter_response['response']
                ]
                response_count = len(page)
                if page:
                    yield page
            else:
                _log_request_failure(
                    helper, iter_response, body_dict.get('page', 'n/a'),
                    'MC-806'
                )
    finally:
        helper.log_info(
            f"[MC-802] response contains {response_count} records"
            f"{_coverage_suffix(response_count, reported_count)}"
        )

        _discard_report(helper, discarded, limit_checker, 'MC-807')

        if limit_checker:
            limit_checker.log_final_stats()


def get_events(helper, connection, config, body_dict,
               limit_checker=None):
    """
    Fetch events from MISP as a single list.

    List form of iter_event_pages(): it materialises every page, so peak memory
    scales with the number of events fetched. Prefer iter_event_pages() where
    each page can be written onward as it arrives.

    Returns:
        list: List of events
    """
    return [
        event
        for page in iter_event_pages(
            helper, connection, config, body_dict, limit_checker
        )
        for event in page
    ]


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
        'attribute_count': 'attribute_count',
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
            # Left unset when the event carries no timestamp; the caller then
            # falls back to search time instead of raising.
            if f'{prefix}event_timestamp' in event_dict:
                event_dict[f'{prefix}timestamp'] = (
                    event_dict[f'{prefix}event_timestamp']
                )
            result_list.append(event_dict)

    return result_list
