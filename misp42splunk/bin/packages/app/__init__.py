# coding=utf-8
#
# Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

from __future__ import absolute_import, division, print_function, unicode_literals

from .configuration import Configuration
from .connection_pool import ConnectionPool
from .expanded_string import ExpandedString
from .formatting_extensions import formatting_extensions

import ldap3
from .six import text_type, iterkeys, PY3
from .six.moves import filterfalse

_character_map = (
    b'\\00',  # NUL
    b'\\01',  # SOH
    b'\\02',  # STX
    b'\\03',  # ETX
    b'\\04',  # EOT
    b'\\05',  # ENQ
    b'\\06',  # ACK
    b'\\07',  # BEL
    b'\\08',  # BS
    b'\\09',  # HT
    b'\\0A',  # LF
    b'\\0B',  # VT
    b'\\0C',  # FF
    b'\\0D',  # CR
    b'\\0E',  # SO
    b'\\0F',  # SI
    b'\\10',  # DLE
    b'\\11',  # DC1
    b'\\12',  # DC2
    b'\\13',  # DC3
    b'\\14',  # DC4
    b'\\15',  # NAK
    b'\\16',  # SYN
    b'\\17',  # ETB
    b'\\18',  # CAN
    b'\\19',  # EM
    b'\\1A',  # SUB
    b'\\1B',  # ESC
    b'\\1C',  # FS
    b'\\1D',  # GS
    b'\\1E',  # RS
    b'\\1F',  # US
    b' ',
    b'!',
    b'"',
    b'#',
    b'$',
    b'%',
    b'&',
    b'\'',
    b'\\28',  # (
    b'\\29',  # )
    b'\\2A',  # *
    b'+',
    b',',
    b'-',
    b'.',
    b'/',
    b'0',
    b'1',
    b'2',
    b'3',
    b'4',
    b'5',
    b'6',
    b'7',
    b'8',
    b'9',
    b':',
    b';',
    b'<',
    b'=',
    b'>',
    b'?',
    b'@',
    b'A',
    b'B',
    b'C',
    b'D',
    b'E',
    b'F',
    b'G',
    b'H',
    b'I',
    b'J',
    b'K',
    b'L',
    b'M',
    b'N',
    b'O',
    b'P',
    b'Q',
    b'R',
    b'S',
    b'T',
    b'U',
    b'V',
    b'W',
    b'X',
    b'Y',
    b'Z',
    b'[',
    b'\\5C',  # \ (backslash)
    b']',
    b'^',
    b'_',
    b'`',
    b'a',
    b'b',
    b'c',
    b'd',
    b'e',
    b'f',
    b'g',
    b'h',
    b'i',
    b'j',
    b'k',
    b'l',
    b'm',
    b'n',
    b'o',
    b'p',
    b'q',
    b'r',
    b's',
    b't',
    b'u',
    b'v',
    b'w',
    b'x',
    b'y',
    b'z',
    b'{',
    b'|',
    b'}',
    b'~',
    b'\\7F',  # DEL
    b'\\80',  # <control>
    b'\\81',  # <control>
    b'\\82',  # <control>
    b'\\83',  # <control>
    b'\\84',  # <control>
    b'\\85',  # <control>
    b'\\86',  # <control>
    b'\\87',  # <control>
    b'\\88',  # <control>
    b'\\89',  # <control>
    b'\\8A',  # <control>
    b'\\8B',  # <control>
    b'\\8C',  # <control>
    b'\\8D',  # <control>
    b'\\8E',  # <control>
    b'\\8F',  # <control>
    b'\\90',  # <control>
    b'\\91',  # <control>
    b'\\92',  # <control>
    b'\\93',  # <control>
    b'\\94',  # <control>
    b'\\95',  # <control>
    b'\\96',  # <control>
    b'\\97',  # <control>
    b'\\98',  # <control>
    b'\\99',  # <control>
    b'\\9A',  # <control>
    b'\\9B',  # <control>
    b'\\9C',  # <control>
    b'\\9D',  # <control>
    b'\\9E',  # <control>
    b'\\9F',  # <control>
    b'\\A0',  #   <no-break space>
    b'\\A1',  # ¡
    b'\\A2',  # ¢
    b'\\A3',  # £
    b'\\A4',  # ¤
    b'\\A5',  # ¥
    b'\\A6',  # ¦
    b'\\A7',  # §
    b'\\A8',  # ¨
    b'\\A9',  # ©
    b'\\AA',  # ª
    b'\\AB',  # «
    b'\\AC',  # ¬
    b'\\AD',  # ­
    b'\\AE',  # ®
    b'\\AF',  # ¯
    b'\\B0',  # °
    b'\\B1',  # ±
    b'\\B2',  # ²
    b'\\B3',  # ³
    b'\\B4',  # ´
    b'\\B5',  # µ
    b'\\B6',  # ¶
    b'\\B7',  # ·
    b'\\B8',  # ¸
    b'\\B9',  # ¹
    b'\\BA',  # º
    b'\\BB',  # »
    b'\\BC',  # ¼
    b'\\BD',  # ½
    b'\\BE',  # ¾
    b'\\BF',  # ¿
    b'\\C0',  # À
    b'\\C1',  # Á
    b'\\C2',  # Â
    b'\\C3',  # Ã
    b'\\C4',  # Ä
    b'\\C5',  # Å
    b'\\C6',  # Æ
    b'\\C7',  # Ç
    b'\\C8',  # È
    b'\\C9',  # É
    b'\\CA',  # Ê
    b'\\CB',  # Ë
    b'\\CC',  # Ì
    b'\\CD',  # Í
    b'\\CE',  # Î
    b'\\CF',  # Ï
    b'\\D0',  # Ð
    b'\\D1',  # Ñ
    b'\\D2',  # Ò
    b'\\D3',  # Ó
    b'\\D4',  # Ô
    b'\\D5',  # Õ
    b'\\D6',  # Ö
    b'\\D7',  # ×
    b'\\D8',  # Ø
    b'\\D9',  # Ù
    b'\\DA',  # Ú
    b'\\DB',  # Û
    b'\\DC',  # Ü
    b'\\DD',  # Ý
    b'\\DE',  # Þ
    b'\\DF',  # ß
    b'\\E0',  # à
    b'\\E1',  # á
    b'\\E2',  # â
    b'\\E3',  # ã
    b'\\E4',  # ä
    b'\\E5',  # å
    b'\\E6',  # æ
    b'\\E7',  # ç
    b'\\E8',  # è
    b'\\E9',  # é
    b'\\EA',  # ê
    b'\\EB',  # ë
    b'\\EC',  # ì
    b'\\ED',  # í
    b'\\EE',  # î
    b'\\EF',  # ï
    b'\\F0',  # ð
    b'\\F1',  # ñ
    b'\\F2',  # ò
    b'\\F3',  # ó
    b'\\F4',  # ô
    b'\\F5',  # õ
    b'\\F6',  # ö
    b'\\F7',  # ÷
    b'\\F8',  # ø
    b'\\F9',  # ù
    b'\\FA',  # ú
    b'\\FB',  # û
    b'\\FC',  # ü
    b'\\FD',  # ý
    b'\\FE',  # þ
    b'\\FF')  # ÿ


_required_features = (  # Features that are common to Windows Server 2008-2012 R2 Active Directory directory services
    '1.2.840.113556.1.4.800',   # LDAP_CAP_ACTIVE_DIRECTORY_OID
    '1.2.840.113556.1.4.1791',  # LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID
    '1.2.840.113556.1.4.1670',  # LDAP_CAP_ACTIVE_DIRECTORY_V51_OID
    '1.2.840.113556.1.4.1935',  # LDAP_CAP_ACTIVE_DIRECTORY_V60_OID
)


def escape_assertion_value(value):
    """ Escapes the characters of an assertion value as per `RFC-4515 <http://goo.gl/iW5xIE>`_.

    :param value: Assertion value to escape
    :type value: unicode/str(depends on python version):
    :return: Escaped assertion value
    :rtype: str

    """
    value = text_type(value)

    def escape_character(c):
        o = ord(c)
        if o > 0xFF:
            escaped_character = c.encode('utf-8')
        else:
            escaped_character = _character_map[o]
        return escaped_character

    escaped_value = b''.join([escape_character(c) for c in value])
    
    if PY3:
        escaped_value = escaped_value.decode('utf-8')
    
    return escaped_value


def get_attributes(command, result):

    result_type = result['type']

    if result_type == 'searchResEntry':
        attributes = result['attributes']._store  # protected member contains serializable data
        return attributes

    if result_type != 'searchResRef':
        message = 'Unexpected search result: {0}\nPlease report this problem to Splunk support'.format(result)
        command.error_exit(ValueError(message), message)

    command.logger.debug('[TAG-3372] Skipped search result referral: %s', result)
    return None


def get_ldap_error_message(error, configuration):

    # TODO: TAG-8843, SA-ldapsearch | ldap3 package sometimes returns messages containing '\x00' characters
    # Remove this workaround when this issue is addressed: message.replace(u'\x00', '')
    # Example: The message produced for LDAPInvalidCredentialsResult
    error_message = str(error).replace('\0', '')

    if not isinstance(error, ldap3.core.exceptions.LDAPInvalidCredentialsResult):
        return error_message

    try:
        error_code = int(error_message.split(', ')[2][len('data '):], 16)
    except:
        error_code = 0x52e  # invalid credentials

    if error_code == 0x525:
        message = 'There is no user with binddn="{0}".'
    elif error_code == 0x533:  # account-disabled
        message = 'The account for the user with binddn="{0}" is disabled.'
    elif error_code == 0x701:  # account-expired
        message = 'The account for the user with binddn="{0}" is expired.'
    elif error_code == 0x775:  # account-locked
        message = 'The account for the user with binddn="{0}" is locked out.'
    elif error_code == 0x531:  # account-restricted-location
        message = 'The user with binddn="{0}" is not permitted to logon from this location.'
    elif error_code == 0x530:  # account-restricted-time
        message = 'The user with binddn="{0}" is not permitted to logon at this time.'
    elif error_code == 0x532:  # password-expired
        message = 'The password for the user with binddn="{0}" is expired.'
    elif error_code == 0x773:  # password-reset-required
        message = 'The password for the user with binddn="{0}" must be reset.'
    else:
        message = 'Invalid credentials for the user with binddn="{0}".'

    message += ' Please correct and test your SA-ldapsearch credentials in the context of domain="{1}"'
    return message.format(configuration.credentials.username, configuration.domain)


def get_normalized_attribute_names(names, connection, configuration):
    """ Gets the normalized attribute names specified by the given list of names.

    :param collections.Iterable names: A list of names specifying the normalized attribute names to be returned. If
        '*' is listed, all normalized user attribute names are returned.  If '+' is listed and the Directory System
        Agent (DSA) associated with :paramref:`connection` supports "All Operational Attributes" as per
        `RFC 3673 <http://goo.gl/YLHoxT>`, all normalized operational attribute names are returned.

    .. note::
        Microsoft Active Directory does not support "All Operational Attributes". Hence, if '+' is listed and the DSA
        associated with :paramref:`connection` is a DSA for Microsoft Active Directory, it is ignored. Operational
        attributes must be explicitly named.

    :param ldap3.Connection connection: A connection to an LDAP server.

    :return: List of normalized attribute names.

    :raises ldap3.LDAPAttributeError: if :paramref:`names` contains invalid attributes.

    """

    # Look to see if "All Operational Attributes is supported by the DSA associated with connection

    supported_features = connection.server.info.supported_features
    required_features_countdown = len(_required_features)
    supports_all_operational_attributes = False
    is_microsoft_active_directory = True

    for feature in supported_features:
        if feature[0] == '1.3.6.1.4.1.4203.1.5.1':  # This DSA supports "All Operational Attributes" as per RFC 3673
            supports_all_operational_attributes = True
            break
        if feature[3] != 'MICROSOFT':
            is_microsoft_active_directory = False
        if feature[0] in _required_features:
            required_features_countdown -= 1

    if not (is_microsoft_active_directory and required_features_countdown == 0):
        configuration.command.logger.warning(
            'The agent at %s is not a Microsoft Windows Server 2008-2012 R2 Active Directory services system agent: '
            '%s', connection.server.name, supported_features)

    if connection.server.schema is None:
        message = 'Failed to retrieve schema information from the directory system agent at {0}'.format(
            connection.server)
        raise ldap3.core.exceptions.LDAPBindError(message)

    # Uniquify names to eliminate duplicates, discarding '+', if "All Operational Attributes" is unsupported

    names = set(names)

    if not supports_all_operational_attributes:
        names.discard('+')

    # Get the list of normalized attribute names from the directory schema

    attribute_types = connection.server.schema.attribute_types

    if names.issubset({ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES}):
        return list(attribute_types)

    normalized_attribute_names = []
    undefined_names = []

    if ldap3.ALL_ATTRIBUTES in names or ldap3.ALL_OPERATIONAL_ATTRIBUTES in names:
        undefined_names.extend(filterfalse(
            lambda n: n in attribute_types or n in (ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES), names))
        if not undefined_names:
            normalized_attribute_names.extend(iterkeys(attribute_types))
    else:
        for name in names:
            try:
                normalized_attribute_names.append(attribute_types[name].name[0])
            except KeyError:
                undefined_names.append(name)
            pass

    if undefined_names:
        raise ldap3.core.exceptions.LDAPAttributeError('Invalid attribute types in attrs list: {0}'.format(', '.join(undefined_names)))

    return normalized_attribute_names
