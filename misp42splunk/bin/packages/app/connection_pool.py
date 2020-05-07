# coding=utf-8
#
# Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function, unicode_literals

from collections import OrderedDict

import app
import ldap3
from .six import itervalues
from .six.moves import filter


class ConnectionPool(object):
    """
    Represents the set of domains defined in ldap.conf as a set of LDAP Connection objects.

    This class supports domain name selection by the ldapfetch, ldapfilter, and ldapgroup commands. These commands
    :py:meth:`~ConnectionPool.select` a domain to query for each input event record they process. Connections are
    instantiated and opened on first use and closed on :py:meth:`~ConnectionPool.__exit__`.

    """
    def __init__(self, configuration, attributes):
        self.configuration = configuration
        self.connections = OrderedDict()
        self.attributes = attributes

    def __enter__(self):
        self.attributes = app.get_normalized_attribute_names(self.attributes, self.select('default'), self.configuration)
        return self

    def __exit__(self, exception_type, exception, traceback):
        for connection in filter(None, itervalues(self.connections)):
            try:
                connection.unbind()
            except Exception as error:
                # Socket is sometimes closed before the connection.strategy.close method is called by connection.unbind
                # Further, for reasons yet to be ascertained, the error caught by Python at this site is NOT recognized
                # for what it is: an ldap3.LDAPSocketCloseError. Hence, we catch any exception here and--for now--
                # hope for the best.
                # TODO: Get a fix to this issue when we next update ldap3 or pin it on the Python runtime and let it be
                self.configuration.command.logger.debug('Swallowed exception of type %s: %s', type(error), error)
                pass

        self.configuration.command.logger.debug('Re-raise exception type: %s', exception_type)
        return exception_type is None  # meaning: do not swallow, but re-raise any exception presented by the runtime

    def select(self, domain):

        connection = self.connections.get(domain)

        if connection is None:

            configuration = self.configuration
            try:
                configuration.select(domain)
            except KeyError:
                self.connections[domain] = connection = None
            else:
                connection = ldap3.Connection(
                    configuration.server,
                    read_only=True,
                    raise_exceptions=True,
                    user=configuration.credentials.username,
                    password=configuration.credentials.password)

                connection.bind()
                self.connections[domain] = connection

        return connection
