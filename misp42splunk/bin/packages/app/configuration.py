# coding=utf-8
#
# Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function, unicode_literals
from collections import namedtuple, OrderedDict
from base64 import b64decode
import os
import ssl
import sys
from functools import reduce as reduce

from ldap3 import Server, Tls, core, ALL
from splunklib.searchcommands.validators import Boolean, Integer, List, Map
from splunklib.binding import HTTPError
from splunklib import data
import app
from .six import itervalues


try:
    from ssl import create_default_context  # New in version 2.7.9
    use_ssl_context = True
except ImportError:
    use_ssl_context = False

class Configuration(object):
    Credentials = namedtuple('Credentials', ['realm', 'username', 'password', 'authorization_id'])
    _tls = None

    def __init__(self, command, is_expanded=False):

        if command.debug:  # debug option overrides logging_level option and logging.conf level setting
            command.logging_level = 'DEBUG'

        self._buffered_configurations = None
        self.command = command
        self.domain = None
        self.settings = None

        # All settings are ultimately reduced to these in Configuration._reset_fields

        self.alternatedomain = None
        self.basedn = None
        self.server = None
        self.credentials = None
        self.decode = None
        self.paged_size = None

        command.logger.debug('Command = %s', command)

        if is_expanded:
            self._read_all_configurations()
        else:
            self._read_configuration()

        return

    def __str__(self):
        username = self.credentials.username
        text = '{0}(server={1}, credentials={2}, alternatedomain={3}, basedn={4}, decode={5}, paged_size={6})'.format(
            self.command.name, self.server, username, self.alternatedomain, self.basedn, self.decode, self.paged_size)
        return text

    def open_connection_pool(self, attributes):
        return app.ConnectionPool(self, attributes)

    def select(self, domain):
        settings = self._buffered_configurations[domain]
        self._reset_fields(settings[0][0], settings[1])

    # region Privates

    def _add_buffered_configuration(self, domain, settings):

        alternatedomain = settings.get('alternatedomain')

        self._ensure_unique_configuration_names(domain, alternatedomain)
        self._buffered_configurations[domain] = ((domain, alternatedomain), settings)

        if alternatedomain:
            self._buffered_configurations[alternatedomain] = ((domain, alternatedomain), settings)

        return

    def _ensure_unique_configuration_names(self, domain, alternatedomain):

        existing_configuration = self._buffered_configurations.get(domain)

        if existing_configuration:
            existing_domain, existing_alternatedomain = existing_configuration[0]
            assert domain != existing_domain  # Configuration system guarantees stanza names are unique within a file
            assert domain == existing_alternatedomain
            message = 'Domain {0} clashes with alternatedomain = {1} in [{2}].'.format(
                domain, existing_alternatedomain, existing_domain)
            self.command.error_exit(ValueError(message), message)

        if alternatedomain:

            existing_configuration = self._buffered_configurations.get(alternatedomain)

            if existing_configuration:

                existing_domain, existing_alternatedomain = existing_configuration[0]

                if alternatedomain == domain or alternatedomain == existing_domain:
                    message = 'Alternate domain {0} in [{1}] clashes with domain = [{2}].'.format(
                            alternatedomain, domain, existing_domain)
                    self.command.error_exit(ValueError(message), message)

                if alternatedomain == existing_alternatedomain:
                    message = 'Alternate domain {0} in [{1}] clashes with alternatedomain = {2} in [{3}]'.format(
                            alternatedomain, domain, existing_alternatedomain, existing_domain)
                    self.command.error_exit(ValueError(message), message)

        return

    def _get_tls(self):
        """
        Gets the TLS configuration of the application.

        The default TLS configuration is obtained from the sslConfig stanza in server.conf. The application may
        selectively override the defaults by specifying sslConfig settings in the custom sslConfig stanza in
        local/ssl.conf. Settings are retrieved from configuration just once, the first time this method is called.

        Differences between SA-ldapsearch and Splunk's treatment of `sslConfig` settings
        --------------------------------------------------------------------------------
        SA-ldapsearch is a pure Python application that executes in the runtime that ships with Splunk 6.0+:

        +------------------+----------------+
        | Splunk version   | Python version |
        +==================+================+
        | Splunk 6.0       | Python 2.7.5   |
        +------------------+----------------+
        | Splunk 6.1       | Python 2.7.5   |
        +------------------+----------------+
        | Splunk 6.2       | Python 2.7.8   |
        +------------------+----------------+
        | Splunk 6.3       | Python 2.7.9   |
        +------------------+----------------+

        SA-ldapsearch depends on the Python :module:`ssl` module for SSL support and some features that Splunk lets
        you configure are missing from this module in versions of Python prior to 2.7.9

        1. Specific support for TLS 1.1 and TLS 1.2
           Prior to Python 2.7.9:
           You can specify an `sslVersions` value of `tls` to negotiate for TLS 1.0, TLS 1.1, or TLS 1.2. You can
           specifically request TLS 1.0 by specifying an `sslVersions value of `tls1.0`. However, you cannot specify
           any combination of `sslVersions` that includes `tls1.1` or `tls1.2`.
           under Python 2.7.9:
           You can specifically request TLS 1.0, 1.1, or 1.2 by specifying an sslVersions value of 'tls1.0', 'tls1.1',
           or 'tls1.2'

        2. Password protected private key files used in mutual authentication
           If you want to configure SA-ldapsearch for mutual authentication, you cannot password protect the file
           identified by `sslKeysfile` and the value of `sslKeysfilePassword` must be left blank.

        Splunk `sslConfig` to ldap3.Tls settings map
        --------------------------------------------

        Here is the mapping between sslConfig settings and the arguments to :meth:`Tls.__init__`.

        +-------+--------------------------------+-------------------------+-------------------------------------------+
        | Supp. | Tls.__init__ argument          | sslConfig setting       | Description                               |
        +=======+================================+=========================+===========================================+
        |   no  | ca_certs_data[1]_              | #N/A                    | String containing the PEM- or DER-        |
        |       |                                |                         | formatted certificates of the             |
        |       |                                |                         | certification authorities.                |
        +-------+--------------------------------+-------------------------+-------------------------------------------+
        |  yes  | ca_certs_file                  | os.path.join(           | File containing the certificates of the   |
        |       |                                |   caPath, caCertFile)   | certification authorities.                |
        +-------+--------------------------------+-------------------------+-------------------------------------------+
        |  yes  | #N/A                           | caPath                  | Path to directory containing caCertFile   |
        |       |                                |                         | and sslKeysfile.                          |
        +-------+--------------------------------+-------------------------+-------------------------------------------+
        |   no  | ca_certs_path[1]_              | #N/A                    | Path to directory containing the          |
        |       |                                |                         | certification certificates authorities.   |
        +-------+--------------------------------+-------------------------+-------------------------------------------+
        |  yes  | local_certificate_file         | os.path.join(           | File with the certificate of the client   |
        |       |                                |   caPath, sslKeysfile)  |                                           |
        +-------+--------------------------------+-------------------------+-------------------------------------------+
        |  yes  | local_private_key_file         | os.path.join(           | File with the private key of the client   |
        |       |                                |   caPath, sslKeysfile)  |                                           |
        +-------+--------------------------------+-------------------------+-------------------------------------------+
        |   no  | local_private_key_password[1]_ | sslKeysfilePassword[2]_ | Password required to access               |
        |       |                                |                         | local_certificate_file.                   |
        +-------+--------------------------------+-------------------------+-------------------------------------------+
        |  yes  | validate                       | sslVerifyServerCert     | Specifies if the server certificate must  |
        |       |                                |                         | be validated.                             |
        +-------+--------------------------------+-------------------------+-------------------------------------------+
        |  yes  | valid_names                    | sslCommonNameToCheck,   | List of valid host names. The matching    |
        |       |                                | sslCommonNameList,      | algorithm used is as outlined in          |
        |       |                                | sslAltNameToCheck       | `RFC-2818 <http://goo.gl/9nVMfp>`_ and    |
        |       |                                |                         | `RFC-6125 <http://goo.gl/QfWKVn>`_ except |
        |       |                                |                         | that IP addresses are not currently       |
        |       |                                |                         | supported. See `ssl.match_hostname        |
        |       |                                |                         | <http://goo.gl/IWgnEK>`_ for additional   |
        |       |                                |                         | information.                              |
        +-------+--------------------------------+-------------------------+-------------------------------------------+
        |  yes  | version                        | sslVersions             | SSL or TLS version to use.                |
        +-------+--------------------------------+-------------------------+-------------------------------------------+
        .. [1] Requires `ssl.SSLContext <http://goo.gl/c0aI0s>`_ which is new in Python 2.7.9/3.2.
        .. [2] Password protected SSL Keys Files are unsupported because we do not have access to `ssl.SSLContext
               <http://goo.gl/c0aI0s>`_.

        :return: TLS configuration of the app.
        :rtype: Tls

        References
        ----------
        1. `Securing Splunk Enterprise: About securing Splunk with SSL <http://goo.gl/7IUFs9>`_
        2. `Splunk Admin Manual: server.conf <http://goo.gl/HpkMYA>`_
        3. `Microsoft Active Directory: Using SSL/TLS <http://goo.gl/3wE2Fa>`_
        4. `Microsoft TechNet: LDAP over SSL (LDAPS) Certificate <http://goo.gl/qnBg41>`_
        5. `RFC-2818: HTTP Over TLS <http://goo.gl/9nVMfp>`_
        6. `RFC-6125: Representation and Verification of Domain-Based Application Service Identity within Internet
           Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)
           <http://goo.gl/QfWKVn>`_
        7. `ldap3: SSL & TLS <http://goo.gl/3P1vjG>`_
        8. `ssl — TLS/SSL wrapper for socket objects: ssl.match_hostname(cert, hostname) <http://goo.gl/IWgnEK>`_

        """
        if Configuration._tls:
            return Configuration._tls

        command = self.command

        configuration_file = command.service.confs[str('ssl')]

        try:
            app_settings = configuration_file['sslConfig']
        except KeyError as error:
            message = 'Cannot use SSL because the sslConfig stanza is missing from ssl.conf.'
            command.error_exit(error, message)
            return

        configuration_file = command.service.confs[str('server')]

        try:
            server_settings = configuration_file['sslConfig']
        except KeyError as error:
            message = 'Cannot use SSL because the sslConfig stanza is missing from server.conf.'
            command.error_exit(error, message)
            return

        def get_ssl_configuration_setting(setting_name, default=None, require=None, validate=None):
            default = self._get_value(server_settings, setting_name, default=default, validate=validate)
            value = self._get_value(app_settings, setting_name, default=default, require=require, validate=validate)
            return value

        ca_path = os.path.expandvars(get_ssl_configuration_setting('caPath', default=''))
        ca_cert_file = get_ssl_configuration_setting('caCertFile', default='')

        if ca_path:
            ca_cert_file = os.path.join(ca_path, ca_cert_file) if ca_cert_file else None

        ssl_verify_server_cert = get_ssl_configuration_setting('sslVerifyServerCert', default=False, validate=Boolean())

        ssl_versions = get_ssl_configuration_setting('sslVersions', default='', validate=List())
        protocol_set = set()

        for ssl_version in ssl_versions:

            if ssl_version[0] == '-':
                operation = protocol_set.difference_update
                member = ssl_version[1:]
            else:
                operation = protocol_set.update
                member = ssl_version

            if member not in ('*', 'ssl2', 'ssl3', 'tls', 'tls1.0', 'tls1.1', 'tls1.2'):
                message = 'SSL configuration issue: sslVersions="{0}" is unrecognized.'.format(ssl_versions)
                command.error_exit(ValueError(message), message)
                return

            if member == '*':
                member = ('ssl2', 'ssl3', 'tls1.0', 'tls1.1', 'tls1.2')
            elif member == 'tls':
                member = ('tls1.0', 'tls1.1', 'tls1.2')
            else:
                member = (member,)

            operation(member)

        if use_ssl_context:  # python 2.7.9
            tls = self.get_tls_python_2_7_9_or_later(command, protocol_set, ssl_versions, ca_cert_file, ssl_verify_server_cert)
        else:    #prior to python 2.7.9
            tls = self.get_tls_python_2_7_8_or_earlier(command, protocol_set, ssl_versions, ca_cert_file, ssl_verify_server_cert)

        Configuration._tls = tls
        return tls

    def get_tls_python_2_7_9_or_later(self, command, protocol_set, ssl_versions, ca_cert_file, ssl_verify_server_cert):

        ssl_no_v2 = False
        ssl_no_v3 = False

        if not protocol_set.symmetric_difference(('ssl3', 'tls1.0', 'tls1.1', 'tls1.2')):
            version = ssl.PROTOCOL_SSLv23
            ssl_no_v2 = True
        elif not protocol_set.symmetric_difference(('tls1.0', 'tls1.1', 'tls1.2')):
            ssl_no_v2 = True
            ssl_no_v3 = True
            version = ssl.PROTOCOL_SSLv23
        elif not protocol_set.symmetric_difference(('ssl3',)):
            version = ssl.PROTOCOL_SSLv3
        elif not protocol_set.symmetric_difference(('tls1.0',)):
            version = ssl.PROTOCOL_TLSv1
        elif not protocol_set.symmetric_difference(('tls1.1',)):
            version = ssl.PROTOCOL_TLSv1_1
        elif not protocol_set.symmetric_difference(('tls1.2',)):
            version = ssl.PROTOCOL_TLSv1_2
        else:
            message = 'SSL configuration issue: sslVersions="{0}" is an invalid combination.'.format(ssl_versions)
            command.error_exit(ValueError(message), message)
            return

        try:
            tls = Tls(
                ca_certs_file=ca_cert_file if ca_cert_file else None,
                validate=ssl.CERT_REQUIRED if ssl_verify_server_cert else ssl.CERT_NONE,
                version=version)
        except core.exceptions.LDAPSSLConfigurationError as error:
            message = 'SSL configuration issue: {0}'.format(error)
            command.error_exit(error, message)
            return

        if ssl_no_v2==False or ssl_no_v3==False:
            command.logger.warning(
                'POODLE Vulnerable: "sslVersions = %s". Upgrade Splunk and disable ssl2 and ssl3 to mitigate this '
                'issue. Consider using "sslVersions = tls". See "Splunk response to SSLv3 POODLE vulnerability '
                '(CVE-2014-3566)" at http://www.splunk.com/view/SP-CAAANKE for additional information.', ssl_versions)
            pass

        return tls

    def get_tls_python_2_7_8_or_earlier(self, command, protocol_set, ssl_versions, ca_cert_file, ssl_verify_server_cert):

        if hasattr(ssl, 'PROTOCOL_SSLv23_NO23'):
            is_poodle_vulnerable_splunk = False
        else:
            is_poodle_vulnerable_splunk = True
            ssl.PROTOCOL_SSLv23_NO23 = 5  # intentionally provokes an error that's treated as a configuration error later

        if not protocol_set.symmetric_difference(('ssl2', 'ssl3', 'tls1.0', 'tls1.1', 'tls1.2')):
            version = ssl.PROTOCOL_SSLv23
        elif not protocol_set.symmetric_difference(('ssl3', 'tls1.0', 'tls1.1', 'tls1.2')):
            version = ssl.PROTOCOL_SSLv23_NO2
        elif not protocol_set.symmetric_difference(('tls1.0', 'tls1.1', 'tls1.2')):
            version = ssl.PROTOCOL_SSLv23_NO23
        elif not protocol_set.symmetric_difference(('ssl2',)):
            version = ssl.PROTOCOL_SSLv2
        elif not protocol_set.symmetric_difference(('ssl3',)):
            version = ssl.PROTOCOL_SSLv3
        elif not protocol_set.symmetric_difference(('tls1.0',)):
            version = ssl.PROTOCOL_TLSv1
        else:
            message = 'SSL configuration issue: sslVersions="{0}" is an invalid combination.'.format(ssl_versions)
            command.error_exit(ValueError(message), message)
            return

        try:
            tls = Tls(
                ca_certs_file=ca_cert_file if ca_cert_file else None,
                validate=ssl.CERT_REQUIRED if ssl_verify_server_cert else ssl.CERT_NONE,
                version=version)
        except core.exceptions.LDAPSSLConfigurationError as error:
            message = 'SSL configuration issue: {0}'.format(error)
            command.error_exit(error, message)
            return

        if is_poodle_vulnerable_splunk:
            command.logger.warning(
                'POODLE Vulnerable: "sslVersions = %s". Upgrade Splunk and disable ssl2 and ssl3 to mitigate this '
                'issue. Consider using "sslVersions = tls". See "Splunk response to SSLv3 POODLE vulnerability '
                '(CVE-2014-3566)" at http://www.splunk.com/view/SP-CAAANKE for additional information.', ssl_versions)
            pass
        elif version not in (ssl.PROTOCOL_SSLv23_NO23, ssl.PROTOCOL_TLSv1):
            command.logger.warning(
                'POODLE Vulnerable: "sslVersions = %s". Disable ssl2 and ssl3 to mitigate this issue. Consider using '
                '"sslVersions = tls". See "Splunk response to SSLv3 POODLE vulnerability (CVE-2014-3566)" at '
                'http://www.splunk.com/view/SP-CAAANKE for additional information.', ssl_versions)
            pass

        return tls

    def _get_value(self, settings, setting_name, require=None, default=None, validate=None):
        # Because the Splunk Python SDK does not respect the semantics of dict type that it inherits from we cannot
        # use settings.get(setting_name, default_value). We must resort to our own helper instead.
        command = self.command
        try:
            value = settings[setting_name]
            if value is None or len(value) == 0:
                raise KeyError
            if validate is not None:
                try:
                    value = validate(value)
                except ValueError as e:
                    message = 'Illegal value for %s in ldap/%s: %s' % (setting_name, command.domain, e)
                    self.command.logger.error(message)
                    self.command.write_error(message)
                    sys.exit(1)
        except (AttributeError, KeyError):
            if require:
                message = 'Missing required value for %s in ldap/%s.' % (setting_name, command.domain)
                self.command.logger.error(message)
                self.command.write_error(message)
                sys.exit(1)
            value = default

        return value

    def _read_all_configurations(self):

        self._buffered_configurations = OrderedDict()
        settings = self._read_default_configuration()
        self._add_buffered_configuration('default', settings)

        for configuration_stanza in self.command.service.confs[str('ldap')].iter():
            domain = configuration_stanza.name
            settings = configuration_stanza.content
            self._add_buffered_configuration(domain, settings)

    def _read_configuration(self):

        command = self.command
        
        if command.domain == 'default':
            settings = self._read_default_configuration()
        else:
            configuration_file = command.service.confs[str('ldap')]

            try:
                stanza = configuration_file[command.domain]
            except KeyError as error:
                self._read_all_configurations()
                try:
                    self.select(command.domain)
                    return
                except Exception as error:
                    message = 'Cannot find the configuration stanza for domain={0} in ldap.conf.'.format(command.domain)
                    command.error_exit(error, message)
                    return
            settings = stanza.content
        self._reset_fields(command.domain, settings)
        return

    def _read_default_configuration(self):

        command = self.command
        service = command.service
        namespace = service.namespace

        try:
            response = service.get('properties/ldap/default', namespace.owner, namespace.app, namespace.sharing)
        except HTTPError as error:
            command.error_exit(error, 'The default configuration stanza for ldap.conf is missing: ' + str(error))
            return

        body = response.body.read()
        feed = data.load(body)
        entries = feed['feed'].get('entry', ())

        if isinstance(entries, data.Record):
            entries = entries,

        settings = {entry['title']: entry['content'].get('$text', '') for entry in entries}
        return settings

    def _reset_fields(self, domain, settings):

        self.settings = settings
        self.domain = domain
        command = self.command

        self.alternatedomain = self._get_value(settings, 'alternatedomain', require=True)
        self.basedn = self._get_value(settings, 'basedn', require=True)
        host = self._get_value(settings, 'server', require=True, validate=List())
        use_ssl = self._get_value(settings, 'ssl', default=False, validate=Boolean())
        port = self._get_value(settings, 'port', default=636 if use_ssl else 389, validate=Integer(0, 65535))

        binddn = self._get_value(settings, 'binddn')

        storage_passwords = command.service.storage_passwords

        if domain == 'default':
            storage_password_names = 'SA-ldapsearch:default:',
        else:
            domain = reduce(lambda v, c: v + ('\\' + c if c in '\\:' else c), self.domain, 'SA-ldapsearch:') + ':'
            storage_password_names = domain, 'SA-ldapsearch:default:'

        password = None

        for ssl_version in storage_password_names:
            try:
                storage_password = storage_passwords[ssl_version]
                password = storage_password.clear_password
                break
            except HTTPError as e:
                if e.status != 403:
                    raise
                command.logger.debug('Storage password "%s" access denied: %s', ssl_version, e)
                break
            except KeyError as e:
                command.logger.debug('Storage password "%s" not found', ssl_version)

        if password is None:
            password = self._get_value(settings, 'password', default='')
            if password.startswith('{64}'):
                password = b64decode(password[4:])
            pass

        self.decode = self._get_value(settings, 'decode', default=True, validate=Boolean())
        self.paged_size = int(self._get_value(settings, 'paged_size', default=1000, validate=Integer(1, 65535)))

        for option in itervalues(command.options):  # override settings with command option values, if they're present
            if not option.is_set:
                if not option.name == 'domain':
                    if hasattr(self, option.name):
                        option.value = getattr(self, option.name)

        decode = command.decode if hasattr(command, 'decode') else self.decode
        formatter = app.formatting_extensions if decode else None
        tls = self._get_tls() if use_ssl else None

        def create_server(hostname):
            return Server(
                hostname, int(port), use_ssl, formatter=formatter, get_info=ALL,
                allowed_referral_hosts=[('*', True)], tls=tls)

        self.server = create_server(host[0]) if len(host) == 1 else [create_server(h) for h in host]
        self.credentials = Configuration.Credentials(None, binddn, password, None)

        command.logger.debug('Configuration = %s', self)

    # endregion
