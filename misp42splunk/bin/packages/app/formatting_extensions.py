# coding=utf-8
#
# Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function, unicode_literals

import itertools
import struct

from .six import text_type, PY3
from .six.moves import range, map


# References:
# 1. [Security Descriptor String Format](http://goo.gl/4IEHBc).
# 2. [ACE header](http://goo.gl/v8O4aG).
# 3. [ACE strings](http://goo.gl/Y10RdI).
# 4. [Object-specific ACEs](http://goo.gl/gnrgnY).
# 5. [SID String Format Syntax](http://goo.gl/itojP1)
# 6. [Microsoft Windows SDK 8.1](http://goo.gl/FWc2Ay), especially sddl.h and winnt.h.
# 7. [Operational attributes](http://goo.gl/mlX0GW)
# 8. [RFC 3673: Lightweight Directory Access Protocol version 3 (LDAPv3): All Operational Attributes](http://goo.gl/aOawGy).

_ace_type_strings = {

    # Numeric keys are defined in winnt.h and string values are defined in sddl.h

    # Documented at [ACE strings](http://goo.gl/Y10RdI)
    0x00: 'A',   # ACCESS_ALLOWED_ACE_TYPE => SDDL_ACCESS_ALLOWED
    0x01: 'D',   # ACCESS_DENIED_ACE_TYPE => SDDL_ACCESS_DENIED
    0x05: 'OA',  # ACCESS_ALLOWED_OBJECT_ACE_TYPE => SDDL_OBJECT_ACCESS_ALLOWED
    0x06: 'OD',  # ACCESS_DENIED_OBJECT_ACE_TYPE => SDDL_OBJECT_ACCESS_DENIED
    0x02: 'AU',  # SYSTEM_AUDIT_ACE_TYPE => SDDL_AUDIT
    0x03: 'AL',  # SYSTEM_ALARM_ACE_TYPE => SDDL_ALARM
    0x07: 'OU',  # SYSTEM_AUDIT_OBJECT_ACE_TYPE => SDDL_OBJECT_AUDIT
    0x08: 'OL',  # SYSTEM_ALARM_OBJECT_ACE_TYPE => SDDL_OBJECT_ALARM
    0x11: 'ML',  # SYSTEM_MANDATORY_LABEL_ACE_TYPE
    0x09: 'XA',  # ACCESS_ALLOWED_CALLBACK_ACE_TYPE => SDDL_CALLBACK_ACCESS_ALLOWED
    0x0A: 'XD',  # ACCESS_DENIED_CALLBACK_ACE_TYPE => ACCESS_DENIED_CALLBACK_ACE_TYPE
    0x12: 'RA',  # SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => SDDL_RESOURCE_ATTRIBUTE
    0x13: 'SP',  # SYSTEM_SCOPED_POLICY_ID_ACE_TYPE => SDDL_SCOPED_POLICY_ID
    0x0D: 'XU',  # SYSTEM_AUDIT_CALLBACK_ACE_TYPE => SDDL_CALLBACK_AUDIT
    0x0B: 'ZA',  # ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED
    0x0C: 'ZD',  # ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => SDDL_CALLBACK_OBJECT_ACCESS_DENIED

    # Documented at [ACE_HEADER](http://goo.gl/v8O4aG)

    0x04: '',    # Reserved for future use: ACCESS_ALLOWED_COMPOUND_ACE_TYPE
    0x0E: '',    # Reserved for future use: SYSTEM_ALARM_CALLBACK_ACE_TYPE
    0x10: '',    # Reserved for future use: SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE =>

    0x0F: '',    # SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
                 #   Object-specific system-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_OBJECT_ACE:
}

_attribute_syntaxes = {  # Attribute oMSyntax map
    #        Syntax                       attributeSyntax  ASN 1-Encoded OID  Description
    '1':   'Boolean',                    # 2.5.5.8        \x550508           TRUE or FALSE values.
    '2':   'Integer',                    # 2.5.5.9        \x550509           A 32-bit number.
    '4':   'String(Octet)',              # 2.5.5.10       \x55050A           A string of bytes (Octet).
    '6':   'String(Object-Identifier)',  # 2.5.5.2        \x550502           The object identifier.
    '10':  'Enumeration',                # 2.5.5.9        \x550509           A 32-bit enumeration.
    '18':  'String(Numeric)',            # 2.5.5.6        \x550506           A sequence of digits.
    '19':  'String(Printable)',          # 2.5.5.5        \x550505           Printable case-sensitive string.
    '20':  'CaseIgnoreString(Teletex)',  # 2.5.5.4        \x550504           Teletex. Does not differentiate upper case
                                          #                                   and lowercase.
    '22':  'String(IA5)',                # 2.5.5.5        \x550505           IA5-String. Character set is case-
                                          #                                   sensitive.
    '23':  'String(UTC-Time)',           # 2.5.5.11       \x55050B           UTC Time.
    '24':  'String(Generalized-Time)',   # 2.5.5.11       \x55050B           Generalized-Time.
    '27':  'Case-Sensitive String',      # 2.5.5.3        \x550503           General String. Differentiates uppercase
                                          #                                   and lowercase.
    '64':  'String(Unicode)',            # 2.5.5.12       \x55050C           Unicode string.
    '65':  'LargeInteger',               # 2.5.5.16       \x550510           A 64-bit number.
    '66':  'String(NT-Sec-Desc)',        # 2.5.5.15       \x55050F           A Microsoft® Windows NT® Security
                                          #                                   descriptor.
    '127': 'Object'                      # 2.5.5.1        \x550501           The fully qualified name of an object in
                                          #                                   the directory.
                                          # 2.5.5.7        \x550507           A distinguished name plus a binary large
                                          #                                   object.
                                          # 2.5.5.13       \x55050D           Presentation address.
                                          # 2.5.5.14       \x55050E           A DN-String plus a Unicode string.
}

_object_specific_ace_types = {

    0x05,   # ACCESS_ALLOWED_OBJECT_ACE_TYPE
            # Used in a DACL to allow a trustee access to a property or property set on the object, or to limit ACE
            # inheritance to a specified type of child object.

    0x06,   # ACCESS_DENIED_OBJECT_ACE_TYPE
            # Used in a DACL to deny a trustee access to a property or property set on the object, or to limit ACE
            # inheritance to a specified type of child object.

    0x07,   # SYSTEM_AUDIT_OBJECT_ACE_TYPE
            # Used in a SACL to log a trustee's attempts to access a property or property set on the object, or to limit
            # ACE inheritance to a specified type of child object.
}

_well_known_sid_strings = {

    0x00000007: 'AN',   # SDDL_ANONYMOUS
                        # Anonymous logon. The corresponding RID is SECURITY_ANONYMOUS_LOGON_RID.
    0x00000224: 'AO',   # SDDL_ACCOUNT_OPERATORS
                        # Account operators. The corresponding RID is DOMAIN_ALIAS_RID_ACCOUNT_OPS.
    0x0000000B: 'AU',   # SDDL_AUTHENTICATED_USERS
                        # Authenticated users. The corresponding RID is SECURITY_AUTHENTICATED_USER_RID.
    0x00000220: 'BA',   # SDDL_BUILTIN_ADMINISTRATORS
                        # Built-in administrators. The corresponding RID is DOMAIN_ALIAS_RID_ADMINS.
    0x00000222: 'BG',   # SDDL_BUILTIN_GUESTS
                        # Built-in guests. The corresponding RID is DOMAIN_ALIAS_RID_GUESTS.
    0x00000227: 'BO',   # SDDL_BACKUP_OPERATORS
                        # Backup operators. The corresponding RID is DOMAIN_ALIAS_RID_BACKUP_OPS.
    0x00000221: 'BU',   # SDDL_BUILTIN_USERS
                        # Built-in users. The corresponding RID is DOMAIN_ALIAS_RID_USERS.
    0x00000205: 'CA',   # SDDL_CERT_SERV_ADMINISTRATORS
                        # Certificate publishers. The corresponding RID is DOMAIN_GROUP_RID_CERT_ADMINS.
    0x0000023E: 'CD',   # SDDL_CERTSVC_DCOM_ACCESS
                        # Users who can connect to certification authorities using Distributed Component Object Model
                        # (DCOM). The corresponding RID is DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP.
    0x00000001: 'CG',   # SDDL_CREATOR_GROUP
                        # Creator group. The corresponding RID is SECURITY_CREATOR_GROUP_RID.
    0x00000200: 'DA',   # SDDL_DOMAIN_ADMINISTRATORS
                        # Domain administrators. The corresponding RID is DOMAIN_GROUP_RID_ADMINS.
    0x00000203: 'DC',   # SDDL_DOMAIN_COMPUTERS
                        # Domain computers. The corresponding RID is DOMAIN_GROUP_RID_COMPUTERS.
    0x00000204: 'DD',   # SDDL_DOMAIN_DOMAIN_CONTROLLERS
                        # Domain controllers. The corresponding RID is DOMAIN_GROUP_RID_CONTROLLERS.
    0x00000202: 'DG',   # SDDL_DOMAIN_GUESTS
                        # Domain guests. The corresponding RID is DOMAIN_GROUP_RID_GUESTS.
    0x00000201: 'DU',   # SDDL_DOMAIN_USERS
                        # Domain users. The corresponding RID is DOMAIN_GROUP_RID_USERS.
    0x00000207: 'EA',   # SDDL_ENTERPRISE_ADMINS
                        # Enterprise administrators. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_ADMINS.
    0x00000009: 'ED',   # SDDL_ENTERPRISE_DOMAIN_CONTROLLERS
                        # Enterprise domain controllers. The corresponding RID is SECURITY_SERVER_LOGON_RID.
    0x00003000: 'HI',   # SDDL_ML_HIGH
                        # High integrity level. The corresponding RID is SECURITY_MANDATORY_HIGH_RID.
    0x00000004: 'IU',   # SDDL_INTERACTIVE
                        # Interactively logged-on user. This is a group identifier added to the token of a process when
                        # it was logged on interactively. The corresponding logon type is LOGON32_LOGON_INTERACTIVE. The
                        # corresponding RID is SECURITY_INTERACTIVE_RID.
    0x000001F4: 'LA',   # SDDL_LOCAL_ADMIN
                        # Local administrator. The corresponding RID is DOMAIN_USER_RID_ADMIN.
    0x000001F5: 'LG',   # SDDL_LOCAL_GUEST
                        # Local guest. The corresponding RID is DOMAIN_USER_RID_GUEST.
    0x00000013: 'LS',   # SDDL_LOCAL_SERVICE
                        # Local service account. The corresponding RID is SECURITY_LOCAL_SERVICE_RID.
    0x00001000: 'LW',   # SDDL_ML_LOW
                        # Low integrity level. The corresponding RID is SECURITY_MANDATORY_LOW_RID.
    0x00002000: 'ME',  # SDDL_MLMEDIUM
                        # Medium integrity level. The corresponding RID is SECURITY_MANDATORY_MEDIUM_RID.
    0x0000022F: 'MU',   # SDDL_PERFMON_USERS
                        # Performance Monitor users.
    0x0000022C: 'NO',   # SDDL_NETWORK_CONFIGURATION_OPS
                        # Network configuration operators. The corresponding RID is
                        # DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS.
    0x00000014: 'NS',   # SDDL_NETWORK_SERVICE
                        # Network service account. The corresponding RID is SECURITY_NETWORK_SERVICE_RID.
    0x00000002: 'NU',   # SDDL_NETWORK
                        # Network logon user. This is a group identifier added to the token of a process when it was
                        # logged on across a network. The corresponding logon type is LOGON32_LOGON_NETWORK. The
                        # corresponding RID is SECURITY_NETWORK_RID.
    0x00000208: 'PA',   # SDDL_GROUP_POLICY_ADMINS
                        # Group Policy administrators. The corresponding RID is DOMAIN_GROUP_RID_POLICY_ADMINS.
    0x00000226: 'PO',   # SDDL_PRINTER_OPERATORS
                        # Printer operators. The corresponding RID is DOMAIN_ALIAS_RID_PRINT_OPS.
    0x0000000A: 'PS',   # SDDL_PERSONAL_SELF
                        # Principal self. The corresponding RID is SECURITY_PRINCIPAL_SELF_RID.
    0x00000223: 'PU',   # SDDL_POWER_USERS
                        # Power users. The corresponding RID is DOMAIN_ALIAS_RID_POWER_USERS.
    0x0000000C: 'RC',   # SDDL_RESTRICTED_CODE
                        # Restricted code. This is a restricted token created using the CreateRestrictedToken function.
                        # The corresponding RID is SECURITY_RESTRICTED_CODE_RID.
    0x0000022B: 'RD',   # SDDL_REMOTE_DESKTOP
                        # Terminal server users. The corresponding RID is DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS.
    0x00000228: 'RE',   # SDDL_REPLICATOR
                        # Replicator. The corresponding RID is DOMAIN_ALIAS_RID_REPLICATOR.
    0x000001F2: 'RO',   # SDDL_ENTERPRISE_RO_DCs
                        # Enterprise Read-only domain controllers. The corresponding RID is
                        # DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.
    0x00000229: 'RS',   # SDDL_RAS_SERVERS
                        # RAS servers group. The corresponding RID is DOMAIN_ALIAS_RID_RAS_SERVERS.
    0x0000022A: 'RU',   # SDDL_ALIAS_PREW2KCOMPACC
                        # Alias to grant permissions to accounts that use applications compatible with operating systems
                        # previous to Windows 2000. The corresponding RID is DOMAIN_ALIAS_RID_PREW2KCOMPACCESS.
    0x00000206: 'SA',   # SDDL_SCHEMA_ADMINISTRATORS
                        # Schema administrators. The corresponding RID is DOMAIN_GROUP_RID_SCHEMA_ADMINS.
    0x00004000: 'SI',   # SDDL_ML_SYSTEM
                        # System integrity level. The corresponding RID is SECURITY_MANDATORY_SYSTEM_RID.
    0x00000225: 'SO',   # SDDL_SERVER_OPERATORS
                        # Server operators. The corresponding RID is DOMAIN_ALIAS_RID_SYSTEM_OPS.
    0x00000006: 'SU',   # SDDL_SERVICE
                        # Service logon user. This is a group identifier added to the token of a process when it was
                        # logged as a service. The corresponding logon type is LOGON32_LOGON_SERVICE. The corresponding
                        # RID is SECURITY_SERVICE_RID.
    0x00000012: 'SY',   # SDDL_LOCAL_SYSTEM
                        # Local system. The corresponding RID is SECURITY_LOCAL_SYSTEM_RID.
}


def format_acl(value, offset):
    """
    :param value:
    :param offset:
    :return:

    """
    acl_start = struct.unpack_from(b'I', value, offset)[0]
    acl_size, ace_count = struct.unpack_from(b'HH', value, acl_start + 2)
    ace_start = acl_start + 8

    text = ''

    for i in range(0, ace_count):

        ace_type, ace_flags, ace_size, rights = struct.unpack_from(b'BBHI', value, ace_start)
        ace_type_string = _ace_type_strings[ace_type]

        ace_flags_string = ''.join((
            'CI' if ace_flags & 0x02 else '',  # CONTAINER_INHERIT_ACE => SDDL_CONTAINER_INHERIT
            'OI' if ace_flags & 0x01 else '',  # OBJECT_INHERIT_ACE => SDDL_OBJECT_INHERIT
            'NP' if ace_flags & 0x04 else '',  # NO_PROPAGATE_INHERIT_ACE => SDDL_NO_PROPAGATE
            'IO' if ace_flags & 0x08 else '',  # INHERIT_ONLY_ACE => SDDL_INHERIT_ONLY
            'ID' if ace_flags & 0x10 else '',  # INHERITED_ACE => SDDL_INHERITED
            'SA' if ace_flags & 0x40 else '',  # SUCCESSFUL_ACCESS_ACE_FLAG => SDDL_AUDIT_SUCCESS
            'FA' if ace_flags & 0x80 else '',  # FAILED_ACCESS_ACE_FLAG => SDDL_AUDIT_FAILURE
        ))

        offset = ace_start + 8

        if ace_type in _object_specific_ace_types:
            object_guid = format_guid(value, offset)
            offset += 16
            inherit_object_guid = format_guid(value, offset)
            offset += 16
        else:
            object_guid = inherit_object_guid = ''

        account_sid = format_sid(value, offset, _well_known_sid_strings)

        if account_sid == 'S-1-0-0':
            account_sid = ''

        offset += 16

        if ace_type == 0x12:  # SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE

            from base64 import b16encode

            def unpack_null_terminated_utf16_string(string, start):
                end = start
                while struct.unpack_from(b'H', string, end) != 0:
                    pass
                return '"' + text_type(struct.unpack_from(str(end - start) + 's', string, start)[0], 'utf-16') + '"'

            def unpack_claim_security_attribute_type_int64(string, start):
                return text_type(struct.unpack_from(b'l', string, start)[0])

            def unpack_claim_security_attribute_type_uint64(string, start):
                return text_type(struct.unpack_from(b'L', string, start)[0])

            def unpack_claim_security_attribute_type_octet_string(string, start):
                # See http://msdn.microsoft.com/en-us/library/windows/desktop/hh448485(v=vs.85).aspx
                # TODO: Do not assume 64-bit octet offset as this code does
                octet_offset, octet_length = struct.unpack_from(b'LL', string, start)
                return b16encode((struct.unpack_from(str(octet_length) + 's', string, start)[0])).decode('utf-8')

            def unpack_claim_security_attribute_type_sid(string, start):
                # See http://msdn.microsoft.com/en-us/library/windows/desktop/hh448483(v=vs.85).aspx
                # TODO: Do not assume a 64-bit name offset as this code does
                octet_offset, name_length = struct.unpack_from(b'LL', string, start)
                return format_sid(string, octet_offset)

            claim_name_offset, claim_type, reserved, claim_flags, claim_count = struct.unpack_from(b'IHHII', value, offset)
            offset += 16

            claim_value_offsets = struct.unpack_from(str(claim_count) + 'I', value, offset)
            claim_name = unpack_null_terminated_utf16_string(value, claim_name_offset)

            if claim_type == 0x0001:    # CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64
                claim_values = [unpack_claim_security_attribute_type_int64(value, x) for x in claim_value_offsets]
                claim_type = 'TI'
            elif claim_type == 0x02:    # CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64
                claim_values = [unpack_claim_security_attribute_type_uint64(value, x) for x in claim_value_offsets]
                claim_type = 'TU'
            elif claim_type == 0x03:    # CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING
                claim_values = [unpack_null_terminated_utf16_string(value, x) for x in claim_value_offsets]
                claim_type = 'TS'
            elif claim_type == 0x05:    # CLAIM_SECURITY_ATTRIBUTE_TYPE_SID
                claim_values = [unpack_claim_security_attribute_type_octet_string(value, x) for x in claim_value_offsets]
                claim_type = 'TD'
            elif claim_type == 0x06:    # CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN
                claim_values = [unpack_claim_security_attribute_type_uint64(value, x) for x in claim_value_offsets]
                claim_type = 'TB'
            elif claim_type == 0x10:    # CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING
                claim_values = [unpack_claim_security_attribute_type_octet_string(value, x) for x in claim_value_offsets]
                claim_type = 'TX'
            else:
                # We should never reach this code
                # TODO: log (?)
                claim_values = ()
                claim_type = ''

            text += '(' + ';'.join(
                (
                    ace_type_string,
                    ace_flags_string,
                    hex(rights),
                    object_guid,
                    inherit_object_guid,
                    account_sid,
                    '(' + ','.join(
                        itertools.chain((claim_name, claim_type, text_type(claim_flags)), claim_values)) + ')'
                )) + ')'
        else:
            text += '(' + ';'.join(
                (
                    ace_type_string,
                    ace_flags_string,
                    hex(rights),
                    object_guid,
                    inherit_object_guid,
                    account_sid
                )) + ')'

        ace_start += ace_size

    return text


def format_attribute_syntax(value):
    """ Converts an oMSyntax attribute value to an LDAP syntax name.

    See :data:`attribute_syntaxes` and the MSDN article `LDAP Representations <http://goo.gl/tLZ68s>`_ for a description
    of the LDAP syntaxes supported by Microsoft Active Directory.

    :param value: Decimal string.
    :type value: ``str``
    :return: LDAP syntax name.
    :rtype unicode:

    """
    syntax_name = ' = '.join((value, _attribute_syntaxes.get(value, '')))
    return syntax_name


def format_filetime(value):
    """ Formats a time interval value as an ISO-8601 date/time string.

    **Example:**

    .. codeblock::PowerShell
    $epochTime = New-Object 'System.DateTime' (1970, 1, 1)
    "0x$($epochTime.ToFileTimeUtc().ToString('x8'))"
    # Displays: 0x19db1ded53e8000

    .. codeblock::python
    app.format_time_interval(unicode(0x19db1ded53e8000), 0x))
    # Displays: '1970-01-01T00:00:00Z'

    **Example:**

    .. codeblock::PowerShell
    $dateTime = New-Object 'System.DateTime' (2014, 9, 23, 0, 17, 46, 67)
    "0x$($dateTime.ToFileTimeUtc().ToString('x8'))"
    # Displays: 0x1cfd6c3ccd76a30

    .. codeblock::python
    app.format_time_interval(unicode(0x1cfd6c3ccd76a30))
    # Displays: '2014-09-23T00:17:46.067000Z'

    **References:**

    1. `Microsoft Windows FILETIME structure <http://goo.gl/dXwCCd>`_
    2. `Microsoft Active Directory Interval syntax <http://goo.gl/MOX5ia>`_

    """

    file_time = int(value)

    if file_time in (0x0000000000000000, 0x7FFFFFFFFFFFFFFF):
        return '(never)'

    from datetime import datetime

    epoch_time = 0x019db1ded53e8000

    seconds, hundreds_of_nanoseconds = divmod(file_time - epoch_time, 10000000)
    microseconds = hundreds_of_nanoseconds // 10

    try:
        dt = datetime.utcfromtimestamp(seconds)
    except ValueError:
        text = ''
    else:
        dt = dt.replace(microsecond=microseconds)
        text = dt.isoformat() + 'Z'

    return text


def format_group_type(value):
    """ Converts the base 10 string representation of a 32-bit integer to a sorted list of `Group-Type` names.

    :param unicode value: Base 10 string representation of a 32-bit integer.
    :return list: Sorted list of `Group-Type` names.

    **References:**

    1. `Group-Type attribute <http://goo.gl/hxY43T>`_

    """
    flags = int(value)
    names = []

    # Confirmed: These names are the same as displayed by Active Directory
    #
    #   1. BUILTIN_LOCAL_GROUP      CN=Hyper-V Administrators,CN=Builtin,DC=msapps,DC=local
    #   2. ACCOUNT_GROUP            CN=DnsUpdateProxy,CN=Users,DC=msapps,DC=local
    #   3. RESOURCE_GROUP           CN=DHCP Administrators,CN=Users,DC=msapps,DC=local
    #   4. UNIVERSAL_GROUP          CN=Enterprise Admins,CN=Users,DC=msapps,DC=local
    #   5. SECURITY_ENABLED         CN=DHCP Administrators,CN=Users,DC=msapps,DC=local
    #
    # Unconfirmed but on the web you will find people using these names:
    #
    #   1. APP_BASIC_GROUP
    #   2. APP_QUERY_GROUP
    #
    # See, for example, http://goo.gl/bReghZ.

    if flags & 0x00000001:  # Specifies a group that is created by the system.
        names.append('BUILTIN_LOCAL_GROUP')
    if flags & 0x00000002:
        names.append('ACCOUNT_GROUP')
    if flags & 0x00000004:
        names.append('RESOURCE_GROUP')
    if flags & 0x00000008:
        names.append('UNIVERSAL_GROUP')
    if flags & 0x00000010:  # Specifies an APP_BASIC group for Windows Server Authorization Manager.
        names.append('APP_BASIC_GROUP')
    if flags & 0x00000020:  # Specifies an APP_QUERY group for Windows Server Authorization Manager.
        names.append('APP_QUERY_GROUP')
    if flags & 0x80000000:  # Specifies a security group. If this flag is not set, the group is a distribution group.
        names.append('SECURITY_ENABLED')

    names.sort()
    return names


def format_guid(value, offset=0):
    """ Converts the binary representation of a GUID structure to string form.

    :param bytes value:
    :return unicode:

    """
    value = struct.unpack_from(b'I2H8B', value, offset)
    text = '{0:08x}-{1:04x}-{2:04x}-{3:02x}{4:02x}-{5:02x}{6:02x}{7:02x}{8:02x}{9:02x}{10:02x}'.format(*value)
    return text


def format_instance_type(value):
    """ Converts the base 10 string representation of a 32-bit integer to a list of `Instance-Type` names.

    :param unicode value: Base 10 string representation of a 32-bit integer.
    :return list: Sorted list of `Instance-Type` names.

    **References:**

    1. `Instance-Type attribute <http://goo.gl/vv6wPM>`_

    """

    flags = int(value)
    names = []

    # Confirmed: These are the same values as displayed by Active Directory:
    #
    #   1. IS_NC_HEAD   DC=msapps,DC=local
    #   2. WRITE        CN=david-noble,OU=Staff,DC=msapps,DC=local
    #
    # Unconfirmed:
    #
    #   1. 0x02
    #   2. NC_ABOVE     Some evidence at http://goo.gl/rzBtFg
    #   3. 0x10
    #   4. 0x20

    if flags & 0x00000001:  # The head of naming context.
        names.append('IS_NC_HEAD')
    if flags & 0x00000002:  # This replica is not instantiated.
        names.append('0x02')
    if flags & 0x00000004:  # The object is writable on this directory.
        names.append('WRITE')
    if flags & 0x00000008:  # The naming context above this one on this directory is held.
        names.append('NC_ABOVE')
    if flags & 0x00000010:  # The naming context is under construction for the first time by replication.
        names.append('0x10')
    if flags & 0x00000020:  # The naming context is in the process of being removed from the local DSA.
        names.append('0x20')

    names.sort()
    return names


def format_sam_account_type(value):
    """ Converts the base 10 string representation of a 32-bit integer to a `SAM-Account-Type` name sans `SAM_` prefix.

    :param unicode value: Base 10 string representation of a 32-bit integer.
    :return unicode: `SAM-Account-Type` name sans `SAM_` prefix.

    **References:**

    1. `SAM-Account-Type attribute <http://goo.gl/Aokhf>`_
    2. `ACCOUNT_TYPE Values <http://goo.gl/rdM3dq>`_

    """
    code = int(value)

    # Confirmed: These names are as displayed by Active Directory:
    #
    #   1. ALIAS_OBJECT            DHCP Administrators,CN=Users,DC=msapps,DC=local
    #   2. GROUP_OBJECT            CN=DnsUpdateProxy,CN=Users,DC=msapps,DC=local
    #   3. MACHINE_ACCOUNT         CN=EXCHANGE,CN=Computers,DC=msapps,DC=local
    #   4. NORMAL_USER_ACCOUNT     CN=Splunker,CN=Users,DC=msapps,DC=local
    #
    # Unconfirmed:
    #
    #   1. DOMAIN_OBJECT
    #   2. NON_SECURITY_GROUP_OBJECT
    #   3. NON_SECURITY_ALIAS_OBJECT
    #   4. TRUST_ACCOUNT
    #   5. APP_BASIC_GROUP
    #   6. APP_QUERY_GROUP

    if code == 0x0000000000:
        name = 'DOMAIN_OBJECT'
    elif code == 0x10000000:
        name = 'GROUP_OBJECT'
    elif code == 0x10000001:
        name = 'NON_SECURITY_GROUP_OBJECT'
    elif code == 0x20000000:
        name = 'ALIAS_OBJECT'
    elif code == 0x20000001:
        name = 'NON_SECURITY_ALIAS_OBJECT'
    elif code == 0x30000000:
        name = 'NORMAL_USER_ACCOUNT'
    elif code == 0x30000001:
        name = 'MACHINE_ACCOUNT'
    elif code == 0x30000002:
        name = 'TRUST_ACCOUNT'
    elif code == 0x40000000:
        name = 'APP_BASIC_GROUP'
    elif code == 0x40000001:  # SAM_APP_QUERY_GROUP
        name = 'APP_QUERY_GROUP'
    else:
        name = value

    return name


def format_sid(value, offset=0, rid_map=None):
    """ Converts a SID structure to a SID string.

    :param bytes value: A byte buffer.
    :param int offset: Offset of a SID structure within :paramref:`value`.

    .. codeblock:: c
        typedef struct _SID_IDENTIFIER_AUTHORITY {
            BYTE Value[6];
        } SID_IDENTIFIER_AUTHORITY,*PSID_IDENTIFIER_AUTHORITY,*LPSID_IDENTIFIER_AUTHORITY;

        typedef struct _SID {
            BYTE  Revision;
            BYTE  SubAuthorityCount;
            SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
            DWORD SubAuthority[ANYSIZE_ARRAY];
        } SID, *PISID;

    :return: String representation of the SID starting at `offset` within the `value` buffer. The string format of the
    SID type is described in this MSDN article: `SID String Format Syntax <http://goo.gl/itojP1>`_.

    """

    def unpack_identifier_authority():
        triplet = struct.unpack_from(b'>3H', value, offset + 2)
        result = triplet[2] + (triplet[1] << 16) + (triplet[0] << 32)
        return result

    revision, sub_authority_count = struct.unpack_from(b'BB', value, offset)
    sub_authority_count &= 0xFF  # upper nibble is reserved for future use

    if rid_map is not None:
        rid_offset = offset + 8 + 4 * (sub_authority_count - 1)
        rid = struct.unpack_from(b'I', value, rid_offset)[0]
        try:
            if rid == 0x00000000 and sub_authority_count == 1:
                identifier_authority = unpack_identifier_authority()
                if identifier_authority == 1:    # SECURITY_WORLD_SID_AUTHORITY
                    text = 'WD'
                elif identifier_authority == 3:  # SECURITY_CREATOR_SID_AUTHORITY
                    text = 'CO'
                else:
                    text = '-'.join(('S', text_type(revision), text_type(identifier_authority), text_type(rid)))
            else:
                text = rid_map[rid]
            return text
        except KeyError:
            pass

    identifier_authority = unpack_identifier_authority()
    sub_authorities = struct.unpack_from(str(sub_authority_count) + 'I', value, offset + 8)

    text = '-'.join(itertools.chain(
        (
            'S',
            text_type(revision),
            text_type(identifier_authority) if identifier_authority < 0x100000000 else '{0:#014x}'.format(
                identifier_authority)
        ),
        map(lambda p: text_type(p), sub_authorities)))

    return text


def format_security_descriptor(value):
    """ Converts the binary representation of a Windows security descriptor to its string form.

    This function uses the `Security Descriptor String Format <http://goo.gl/4IEHBc>`_ to represent security
    descriptors.

    :param value: The binary representation of a Windows security descriptor.
    :return: String form of :paramref:`value`.

    """
    start_owner, start_group = struct.unpack_from(b'II', value, 4)
    text = ''

    if start_owner:
        text += 'O:' + format_sid(value, start_owner, _well_known_sid_strings)

    if start_group:
        text += 'G:' + format_sid(value, start_group, _well_known_sid_strings)

    control = struct.unpack_from(b'H', value, 2)[0]

    if control & 0x0004:  # SE_DACL_PRESENT
        text += 'D:'
        if control & 0x1000:  # SE_DACL_PROTECTED
            text += 'P'
        if control & 0x0100:  # SE_DACL_AUTO_INHERIT_REQ
            text += 'AR'
        if control & 0x0400:  # SE_DACL_AUTO_INHERITED:
            text += 'AI'
        text += format_acl(value, 16)

    if control & 0x0010:  # SE_SACL_PRESENT
        text += 'S:'
        if control & 0x2000:  # SE_SACL_PROTECTED
            text += 'P'
        if control & 0x0200:  # SE_SACL_AUTO_INHERIT_REQ
            text += 'AR'
        if control & 0x0800:  # SE_SACL_AUTO_INHERITED:
            text += 'AI'
        text += format_acl(value, 12)

    return text


def format_user_flag_enum(value):
    """ Converts the base 10 string representation of a 32-bit integer to a list of ADS_USER_FLAG_ENUM values.

    :param value: String representation of a 32-bit integer in base 10.
    :return: Sorted list of ADS_USER_FLAG_ENUM values sans `ADS_UF_` prefix.

    **References:**

    1. `ADS_USER_FLAG_ENUM enumeration <http://goo.gl/LN1KMN>`_
    2. `USER_INFO_1008 structure <http://goo.gl/opgkZW>`_
    3. `User-Account-Control attribute <http://goo.gl/Uh9XUr>`_
    4. `ms-DS-User-Account-Control-Computed attribute <http://goo.gl/puRXGs>`_

    """
    flags = int(value)
    names = []

    # Well documented so confidence is high that these names are correct

    # Zero or more these flags may be set

    if flags & 0x0000001:
        names.append('SCRIPT')
    if flags & 0x0000002:
        names.append('ACCOUNTDISABLE')
    if flags & 0x0000008:
        names.append('HOMEDIR_REQUIRED')
    if flags & 0x0000010:
        names.append('LOCKOUT')
    if flags & 0x0000020:
        names.append('PASSWD_NOTREQD')
    if flags & 0x0000040:
        names.append('PASSWD_CANT_CHANGE')
    if flags & 0x0000080:
        names.append('ENCRYPTED_TEXT_PASSWORD_ALLOWED')
    if flags & 0x0010000:
        names.append('DONT_EXPIRE_PASSWD')
    if flags & 0x0020000:
        names.append('MNS_LOGON_ACCOUNT')
    if flags & 0x0040000:
        names.append('SMARTCARD_REQUIRED')
    if flags & 0x0080000:
        names.append('TRUSTED_FOR_DELEGATION')
    if flags & 0x0100000:
        names.append('NOT_DELEGATED')
    if flags & 0x0200000:
        names.append('USE_DES_KEY_ONLY')
    if flags & 0x0400000:
        names.append('DONT_REQUIRE_PREAUTH')
    if flags & 0x0800000:
        names.append('PASSWORD_EXPIRED')
    if flags & 0x1000000:
        names.append('TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION')

    # Zero or one of these flags may be set

    if flags & 0x000000100:
        names.append('TEMP_DUPLICATE_ACCOUNT')
    elif flags & 0x0000200:
        names.append('NORMAL_ACCOUNT')
    elif flags & 0x0001000:
        names.append('WORKSTATION_TRUST_ACCOUNT')
    elif flags & 0x0002000:
        names.append('SERVER_TRUST_ACCOUNT')
    elif flags & 0x0000800:
        names.append('INTERDOMAIN_TRUST_ACCOUNT')

    names.sort()

    return names

def format_unicode(raw_value):
    try:
        if str is not bytes:  # Python 3
            return str(raw_value, 'utf-8', errors='strict')
        else:  # Python 2
            return unicode(raw_value, 'utf-8', errors='strict')
    except (TypeError, UnicodeDecodeError):
        pass

    return raw_value


formatting_extensions = {

    # attributeId values

    '1.2.840.113556.1.2.231':           format_attribute_syntax,       # oMSyntax

    '1.2.840.113556.1.4.159':           format_filetime,               # Account-Expires
    '1.2.840.113556.1.4.49':            format_filetime,               # Bad-Password-Time
    '1.2.840.113556.1.4.13':            format_filetime,               # Builtin-Creation-Time
    '1.2.840.113556.1.4.26':            format_filetime,               # Creation-Time
    '1.2.840.113556.1.4.720':           format_filetime,               # dhcp-Update-Time
    '1.2.840.113556.1.4.519':           format_filetime,               # Last-Backup-Restoration-Time
    '1.2.840.113556.1.4.50':            format_filetime,               # Last-Content-Indexed
    '1.2.840.113556.1.4.51':            format_filetime,               # Last-Logoff
    '1.2.840.113556.1.4.52':            format_filetime,               # Last-Logon
    '1.2.840.113556.1.4.1696':          format_filetime,               # Last-Logon-Timestamp
    '1.2.840.113556.1.4.53':            format_filetime,               # Last-Set-Time
    '1.2.840.113556.1.4.662':           format_filetime,               # Lockout-Time
    '1.2.840.113556.1.4.66':            format_filetime,               # LSA-Creation-Time
    '1.2.840.113556.1.4.2262':          format_filetime,               # ms-DS-Approximate-Last-Logon-Time-Stamp
    '1.2.840.113556.1.4.1442':          format_filetime,               # ms-DS-Cached-Membership-Time-Stamp
    '1.2.840.113556.1.4.1971':          format_filetime,               # ms-DS-Last-Failed-Interactive-Logon-Time
    '1.2.840.113556.1.4.1970':          format_filetime,               # ms-DS-Last-Successful-Interactive-Logon-Time
    '1.2.840.113556.1.4.1996':          format_filetime,               # ms-DS-User-Password-Expiry-Time-Computed
    '1.2.840.113556.1.4.96':            format_filetime,               # Pwd-Last-Set
    '1.2.840.113556.1.4.502':           format_filetime,               # Time-Vol-Change

    '1.2.840.113556.1.4.750':           format_group_type,             # Group-Type

    '1.2.840.113556.1.4.149':           format_guid,                   # Attribute-Security-GUID
    '1.2.840.113556.1.4.533':           format_guid,                   # FRS-Replica-Set-GUID
    '1.2.840.113556.1.4.43':            format_guid,                   # FRS-Version-GUID
    '1.2.840.113556.1.4.1428':          format_guid,                   # ms-COM-ObjectId
    '1.2.840.113556.1.4.2032':          format_guid,                   # ms-DFS-Generation-GUID-v2
    '1.2.840.113556.1.4.2041':          format_guid,                   # ms-DFS-Link-Identity-GUID-v2
    '1.2.840.113556.1.4.2033':          format_guid,                   # ms-DFS-Namespace-Identity-GUID-v2
    '1.2.840.113556.1.6.13.3.18':       format_guid,                   # ms-DFSR-ContentSetGuid
    '1.2.840.113556.1.6.13.3.23':       format_guid,                   # ms-DFSR-ReplicationGroupGuid
    '1.2.840.113556.1.4.1949':          format_guid,                   # ms-DS-Az-Object-Guid
    '1.2.840.113556.1.4.1360':          format_guid,                   # MS-DS-Consistency-Guid
    '1.2.840.113556.1.4.2062':          format_guid,                   # ms-DS-Optional-Feature-GUID
    '1.2.840.113556.1.4.1965':          format_guid,                   # ms-FVE-RecoveryGuid
    '1.2.840.113556.1.4.1998':          format_guid,                   # ms-FVE-VolumeGuid
    '1.2.840.113556.1.4.359':           format_guid,                   # Netboot-GUID
    '1.2.840.113556.1.4.2':             format_guid,                   # Object-Guid
    '1.2.840.113556.1.4.505':           format_guid,                   # OMT-Guid
    '1.2.840.113556.1.4.333':           format_guid,                   # OMT-Indx-Guid
    '1.2.840.113556.1.4.1224':          format_guid,                   # Parent-GUID
    '1.2.840.113556.1.4.205':           format_guid,                   # PKT-Guid
    '1.2.840.113556.1.4.148':           format_guid,                   # Schema-ID-GUID
    '1.2.840.113556.1.4.122':           format_guid,                   # Service-Class-ID
    '1.2.840.113556.1.4.362':           format_guid,                   # Site-GUID
    '1.2.840.113556.1.4.336':           format_guid,                   # Vol-Table-GUID
    '1.2.840.113556.1.4.334':           format_guid,                   # Vol-Table-Idx-GUID

    '1.2.840.113556.1.2.1':             format_instance_type,          # Instance-Type

    '1.2.840.113556.1.4.302':           format_sam_account_type,       # SAM-Account-Type

    '1.2.840.113556.1.4.2154':          format_sid,                    # ms-Authz-Central-Access-Policy-ID
    '1.2.840.113556.1.4.1410':          format_sid,                    # MS-DS-Creator-SID
    '1.2.840.113556.1.4.1844':          format_sid,                    # ms-DS-Quota-Trustee
    '1.2.840.113556.1.4.146':           format_sid,                    # Object-Sid
    '1.2.840.113556.1.4.121':           format_sid,                    # Security-Identifier
    '1.2.840.113556.1.4.609':           format_sid,                    # SID-History
    '1.2.840.113556.1.4.667':           format_sid,                    # Sync-With-SID
    '1.2.840.113556.1.4.1301':          format_sid,                    # Token-Groups
    '1.2.840.113556.1.4.1418':          format_sid,                    # Token-Groups-Global-And-Universal
    '1.2.840.113556.1.4.1303':          format_sid,                    # Token-Groups-No-GC-Acceptable

    '1.2.840.113556.1.4.8':             format_user_flag_enum,         # User-Account-Control

    # formatter specially for msExchMailboxSecurityDescriptor
    '1.2.840.113556.1.4.7000.102.80' : format_security_descriptor,     # msExchMailboxSecurityDescriptor

    #  below formatters are present in standard formatter of ldap3 but for keeping the
    #  consistency in formatting with the previous versions, this formatters are added here.
    '1.2.840.113556.1.4.903':           format_unicode,                # Object (DN-binary) - Microsoft
    '1.2.840.113556.1.4.1221':          format_unicode                 # Object (OR-name) - Microsoft

}
