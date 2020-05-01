import base64
import codecs
import collections
import csv
try:
    import http.client as http_client
except ImportError:
    import httplib as http_client  # noqa
import json
import logging
import logging.handlers
import os
import random
import re
import splunk.rest as rest
import sys
import time

from timeit import default_timer as timer

from splunk.clilib.cli_common import getConfKeyValue
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.util import mktimegm, normalizeBoolean

# Python 2+3 basestring
try:
    basestring
except NameError:
    basestring = str

# set the maximum allowable CSV field size
#
# The default of the csv module is 128KB; upping to 10MB. See SPL-12117 for
# the background on issues surrounding field sizes.
# (this method is new in python 2.5)
csv.field_size_limit(10485760)


def truthy_strint_from_dict(d, k):
    return True if isinstance(d.get(k, None), (basestring, int)) and (d[k] or d[k] == 0) else False


def default_dropexp(x):
    """ The purpose of this method is to determine whether or not
    a key should be dropped.
    """
    return (
        (x.startswith('_') and x not in ['_bkt', '_cd', '_raw', '_time'])
        or x.startswith('date_')
        or x in ['punct', 'sid', 'rid', 'orig_sid', 'orig_rid']
    )


def default_mapexp(x):
    """ The purpose of this method is to determine whether or not
    a key should be mapped to orig_key.
    """
    return (
        x.startswith('tag::')
        or x in [
            '_bkt', '_cd', '_time', '_raw', 'splunk_server', 'index',
            'source', 'sourcetype', 'host', 'linecount',
            'timestartpos', 'timeendpos', 'eventtype',
            'tag', 'search_name', 'event_hash', 'event_id'
        ]
    )


def parse_mv(mvstr):
    grab = False
    escape_idx = None
    vals = []

    for c, char in enumerate(mvstr):
        if char == '$':
            # literal
            if c - 1 == escape_idx:
                escape_idx = None
            elif grab:
                nchar = mvstr[c + 1] if len(mvstr) - 1 > c else None
                # escape
                if nchar == '$':
                    escape_idx = c
                    continue
                # stop
                else:
                    grab = False
                    escape_idx = None
                    continue
            # start
            else:
                grab = True
                vals.append('')
                continue

        if grab:
            vals[-1] += char

    return vals


class InvalidResultID(Exception):
    pass


class ModularActionFormatter(logging.Formatter):
    """ An extension to the logging.Formatter base class
    Hardcodes "+0000" into default datefmt
    Use in conjunction with ModularActionFormatter.converter = time.gmtime
    """

    def formatTime(self, record, datefmt=None):
        """
        Return the creation time of the specified LogRecord as formatted text.

        This method should be called from format() by a formatter which
        wants to make use of a formatted time. This method can be overridden
        in formatters to provide for any specific requirement, but the
        basic behaviour is as follows: if datefmt (a string) is specified,
        it is used with time.strftime() to format the creation time of the
        record. Otherwise, the ISO8601 format is used. The resulting
        string is returned. This function assumes time.gmtime() as the
        'converter' attribute in the Formatter class.
        """
        ct = self.converter(record.created)
        if datefmt:
            s = time.strftime(datefmt, ct)
        else:
            t = time.strftime("%Y-%m-%d %H:%M:%S", ct)
            s = "%s,%03d+0000" % (t, record.msecs)
        return s


class ModularAction(object):
    DEFAULT_MSGFIELDS = [
        'worker',
        'signature',
        'action_name',
        'search_name',
        'sid',
        'orig_sid',
        'rid',
        'orig_rid',
        'app',
        'user',
        'digest_mode',
        'action_mode',
        'action_status'
    ]
    DEFAULT_MESSAGE = 'sendmodaction - {0}'.format(
        ' '.join(['{i}="{{d[{i}]}}"'.format(i=i) for i in DEFAULT_MSGFIELDS]))
    # The above yields a string.format() compatible format string:
    #
    #   'sendmodaction - signature="{d[signature]}" action_name="{d[action_name]}"
    #   search_name="{d[search_name]}" sid="{d[sid]}" orig_sid="{d[orig_sid]}"
    #   rid="{d[rid]}" orig_rid="{d[orig_rid]}" app="{d[app]}" user="{d[user]}"
    #   action_mode="{d[action_mode]}" action_status="{d[action_status]}"'
    # {0} - index, {1} - host, {2} - source

    DEFAULT_HEADER = '***SPLUNK*** %s %s %s'
    DEFAULT_BREAKER = '==##~~##~~  1E8N3D4E6V5E7N2T9 ~~##~~##==\n'
    # {0} - orig_action-name, {1} - orig_sid, {2} - orig_rid, {3} - sourcetype
    DEFAULT_IDLINE = '***Common Action Model*** %s %s %s %s'
    DEFAULT_INDEX = 'summary'
    DEFAULT_CHUNK = 50000

    SHORT_FORMAT = '%(asctime)s %(levelname)s %(message)s'

    CAM_QUEUE_URI = '/servicesNS/nobody/Splunk_SA_CIM/alerts/modaction_queue/queue'

    PRA_RID_RE = re.compile(r'^tmp_(\d+)\..*')

    def __init__(self, settings, logger, action_name='unknown'):
        """ Initialize ModularAction class.

        @param settings:    A modular action payload in JSON format.
        @param logger:      A logging instance.
                            Recommend using ModularAction.setup_logger.
        @param action_name: The action name.
                            action_name in payload will take precedence.
        """
        # used to compute duration
        self.start_timer = timer()

        # worker
        try:
            self.worker = getConfKeyValue('server', 'general', 'serverName')
        except Exception:
            self.worker = ''

        # settings
        self.settings = json.loads(settings)

        # configuration
        self.configuration = self.settings.get('configuration', {})
        if not isinstance(self.configuration, dict):
            self.configuration = {}

        # logger
        self.logger = logger
        # set loglevel to DEBUG if verbose
        verbose = normalizeBoolean(self.configuration.get('verbose', False))
        if verbose is True:
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug('Log level set to DEBUG')

        # replay mode
        replay_mode = normalizeBoolean(
            self.settings.get('_cam_replay', False))
        if replay_mode is True:
            self.replay_mode = replay_mode
            self.logger.info('Replay mode detected')
        else:
            self.replay_mode = False

        # session key
        self.session_key = self.settings.get('session_key')

        # search id
        self.sid = self.settings.get('sid')
        self.sid_snapshot = ''
        # if sid contains rt_scheduler with snapshot-sid; drop snapshot-sid
        # sometimes self.sid may be an integer (1465593470.1228)
        try:
            rtsid = re.match(r'^(rt_scheduler.*)\.(\d+)(_?.*)$', self.sid)
            if rtsid:
                self.sid = rtsid.group(1)
                self.sid_snapshot = rtsid.group(2)
                # CIM-665: SHC realtime alerts have _guidval appended
                if rtsid.group(3):
                    self.sid += rtsid.group(3)
        except Exception:
            pass
        # rid_ntuple is a named tuple that represents
        # the three variables that change on a per-result basis
        self.rid_ntuple = collections.namedtuple('ID', ['orig_sid', 'rid', 'orig_rid'])
        # rids is a list of rid_ntuple values
        # automatically maintained by update() calls
        self.rids = []
        # current orig_sid based on update()
        # aka self.rids[-1].orig_sid
        self.orig_sid = ''
        # current rid based on update()
        # aka self.rids[-1].rid
        self.rid = ''
        # current orig_rid based on update()
        # aka self.rids[-1].orig_rid
        self.orig_rid = ''

        # results_file
        self.results_file = self.settings.get('results_file')
        # results_path
        results_path = ''
        if self.results_file:
            results_path = os.path.dirname(self.results_file)

        # digest_mode (per-result alerting)
        self.digest_mode = 1
        # per SPL-172319 - splunkd to provide result_id for per-result-alerting
        if truthy_strint_from_dict(self.settings, 'result_id'):
            self.digest_mode = 0
        # pre SPL-172319 behavior
        elif results_path.split(os.sep)[-1] == 'per_result_alert':
            self.digest_mode = 0

        # info/job
        self.info = {}
        self.info_file = None
        if self.results_file:
            # handle per-result alerting
            if self.digest_mode == 0:
                self.info_file = os.path.join(
                    os.path.dirname(results_path), 'info.csv')
            else:
                self.info_file = os.path.join(results_path, 'info.csv')
        self.job = {}

        self.search_name = self.settings.get('search_name')
        self.app = self.settings.get('app')
        self.user = self.settings.get('user') or self.settings.get('owner')

        # use | sendalert param.action_name=$action_name$
        self.action_name = self.configuration.get('action_name') or action_name

        # use sid to determine action_mode
        if isinstance(self.sid, basestring) and 'scheduler' in self.sid:
            self.action_mode = 'saved'
        else:
            self.action_mode = 'adhoc'

        self.action_status = ''

        # Since we don't use the result object we get from settings it will be purged
        try:
            del self.settings['result']
        except Exception:
            pass

        # events
        self.events = []

    def addinfo(self):
        """ The purpose of this method is to populate the
        modular action info variable with the contents of info.csv.
        """
        info_data = None

        if self.info_file:
            try:
                with open(self.info_file, 'rb') as fh:
                    fc = codecs.getreader('utf-8')(fh)
                    info_data = fc.read()
                    fh.seek(0)
                    self.info = next(csv.DictReader(fc))
            except Exception:
                self.message(
                    'Could not retrieve info.csv',
                    level=logging.WARN
                )

        return info_data

    def addjobinfo(self):
        """ The purpose of this method is to populate the job variable
        with the contents from REST (/services/search/jobs/<sid>)

        If we're in replay mode we will not be able to hit /services/search/jobs/<sid>

        SPL-112815 - sendalert - not all $job.<param>$ parameters come through
        """
        if self.sid and not self.job and not self.replay_mode:
            try:
                r, c = rest.simpleRequest(
                    'search/jobs/%s' % self.sid,
                    sessionKey=self.session_key,
                    getargs={'output_mode': 'json'}
                )
                if r.status == http_client.OK:
                    self.job = json.loads(c)['entry'][0]['content']
                    self.message('Successfully retrieved search job info')
                    self.logger.debug(self.job)
                else:
                    self.message(
                        'Could not retrieve search job info',
                        level=logging.WARN
                    )
            except Exception:
                self.message(
                    'Could not retrieve search job info',
                    level=logging.WARN
                )

    def message(self, signature, status=None, rids=None, level=logging.INFO, **kwargs):
        """ The purpose of this method is to provide a common messaging interface.

        @param signature: A string representing the message we want to log.
        @param status:    An optional status that we want to log.
                          Defaults to None.
        @param rids:      An optional list of rid_ntuple values in case we
                          want to generate the message for multiple rids.
                          Defaults to None (use the rid currently loaded).
        @param level:     The logging level to use when writing the message.
                          Defaults to logging.INFO (INFO)
        @param kwargs:    Additional keyword arguments to be included with the
                          message.
                          Defaults to "no arguments".

        @return message:  This method logs the message; however, for
                          backwards compatibility we also return the message.
        """
        # worker
        worker = kwargs.get('worker') or self.worker or ''
        # status
        status = status or self.action_status or ''
        # rid
        if not isinstance(rids, list) or rids == []:
            rids = [self.rid_ntuple(self.orig_sid, self.rid, self.orig_rid)]
        # kwargs - prune any duplicate keys based on DEFAULT_MSGFIELDS
        #          prune any keys with special characters [A-Za-z_]+
        newargs = [
            x for x in sorted(kwargs)
            if (x not in ModularAction.DEFAULT_MSGFIELDS) and re.match(r'[A-Za-z_]+', x)
        ]
        # MSG
        msg = '{0} {1}'.format(
            ModularAction.DEFAULT_MESSAGE,
            ' '.join(['{i}="{{d[{i}]}}"'.format(i=i) for i in newargs])
        )

        # This will set the default value of any value NOT in the dictionary to the
        # empty string.
        argsdict = collections.defaultdict(str)
        # order is important here - here we update first from kwargs, then from our
        # expected arg set.
        argsdict.update(kwargs)
        argsdict.update({
            'worker': worker,
            'signature': signature or '',
            'action_name': self.action_name or '',
            'search_name': self.search_name or '',
            'sid': self.sid or '',
            'app': self.app or '',
            'user': self.user or '',
            'digest_mode': self.digest_mode if self.digest_mode in [0, 1] else '',
            'action_mode': self.action_mode or '',
            'action_status': status
        })

        for rid_ntuple in rids:
            if len(rid_ntuple) == 3:
                # Update the arguments dictionary
                argsdict.update({
                    'orig_sid': rid_ntuple.orig_sid or '',
                    'rid': rid_ntuple.rid or '',
                    'orig_rid': rid_ntuple.orig_rid or ''
                })
                # This is where the magic happens. The format string will use the
                # attributes of "argsdict"
                message = msg.format(d=argsdict)
                # prune empty string key-value pairs
                for match in re.finditer(r'[A-Za-z_]+=""(\s|$)', message):
                    message = message.replace(match.group(0), '', 1)
                message = message.strip()
                self.logger.log(level, message)
            else:
                self.logger.warn('Could not unpack rid_ntuple')
                message = ''

        return message

    def update(self, result):
        """ The purpose of this method is to update the ModularAction instance
        identifiers based on the current result being operated on.

        This is the most important method in the library as it sets up
        rid, orig_sid, and orig_rid to be used by subsequent class methods.

        Not calling update() immediately for each result before doing additional
        work can have adverse affects.

        @result: The result dictionary object (arbitrary key/value pairs)
        """
        # This is for events/results that were created as the result of a previous action
        self.orig_sid = result.get('orig_sid', '')
        # This is for events/results that were created as the result of a previous action
        self.orig_rid = result.get('orig_rid', '')

        # If using per-result alerting rid will be decided for you.
        # This is due to the fact that a number of scripts inadvertently
        # set this to 0 based on enumeration.
        if self.digest_mode == 0:
            # per SPL-172319 - splunkd to provide result_id for per-result-alerting
            if truthy_strint_from_dict(self.settings, 'result_id'):
                self.rid = str(self.settings['result_id'])
            # pre SPL-172319 behavior
            else:
                results_file = os.path.basename(self.results_file)
                pra_rid_match = self.PRA_RID_RE.match(results_file)
                if pra_rid_match:
                    self.rid = pra_rid_match.group(1)
                else:
                    raise InvalidResultID('Result must have an ID')

        elif truthy_strint_from_dict(result, 'rid'):
            self.rid = str(result['rid'])

        else:
            raise InvalidResultID('Result must have an ID')

        # add snapshot id
        if self.sid_snapshot:
            self.rid = '%s.%s' % (self.rid, self.sid_snapshot)

        # add result info to list of named tuples
        self.rids.append(
            self.rid_ntuple(self.orig_sid, self.rid, self.orig_rid))

    def invoke(self):
        """ The purpose of this method is to generate per-result invocation messages.
        This method is used to identify that an action is being attempted on a per-result basis.

        Remember to call update() prior to invoke() to ensure that the invocation message
        reflects the appropriate identifiers.
        """
        self.message('Invoking modular action')

    def result2stash(
            self,
            result,
            dropexp=default_dropexp,
            mapexp=default_mapexp,
            addinfo=False):
        """ The purpose of this method is to formulate an event in stash format

        @param result:  The result dictionary to generate a stash event for.
        @param dropexp: A lambda expression used to determine whether a field
                        should be dropped or not.
                        Defaults to default_dropexp.
        @param mapexp:  A lambda expression used to determine whether a field
                        should be mapped (prepended with "orig_") or not.
                        Defaults to default_mapexp.
        @param addinfo: Whether or not to add search information to the event.
                        "info" includes search_now, info_min_time, info_max_time,
                        and info_search_time fields.
                        Requires that information was loaded into the ModularAction
                        instance via addinfo()

        @return _raw:   Returns a string which represents the result in stash format.

        The following example has been broken onto multiple lines for readability:
        06/21/2016 10:00:00 -0700,
        search_name="Access - Brute Force Access Behavior Detected - Rule",
        search_now=0.000, info_min_time=1466528400.000,
        info_max_time=1466532600.000, info_search_time=1465296264.179,
        key1=key1val, key2=key2val, key3=key3val, key4=key4val1, key4=key4val2, ...
        """
        dropexp = dropexp or (lambda x: False)
        mapexp = mapexp or (lambda x: False)

        def orig_dropexp(x):
            """ The purpose of this method is to determine whether we should
            drop an orig_key that will be overwritten by a key to be mapped.

            For instance, if we have orig_foo and foo in result, and foo is a
            mapped key, then orig_foo will be dropped.
            """
            return x.startswith('orig_') and x[5:] in result and mapexp(x[5:])

        # addinfo
        if addinfo:
            result['info_min_time'] = self.info.get('_search_et', '0.000')
            info_max_time = self.info.get('_search_lt')
            if not info_max_time or info_max_time == 0 or info_max_time == '0':
                info_max_time = '+Infinity'
            result['info_max_time'] = info_max_time
            result['info_search_time'] = self.info.get('_timestamp', '')

        # construct _raw
        _raw = '%s' % result.get('_time', mktimegm(time.gmtime()))
        if self.search_name:
            _raw += ', search_name="%s"' % self.search_name.replace('"', r'\"')

        # get key names
        result_keys = set([
            x[5:] if x.startswith('__mv_') else x
            for x in result
        ])

        # iterate keys
        for key in sorted(list(result_keys)):
            if dropexp(key) or orig_dropexp(key):
                continue

            # if key is MV
            mv_key = '__mv_{0}'.format(key)
            if (mv_key in result
                    and isinstance(result[mv_key], basestring)  # string
                    and result[mv_key].startswith('$')  # prefix
                    and result[mv_key].endswith('$')):  # suffix
                vals = parse_mv(result[mv_key])
            # if key is SV
            elif key in result:
                vals = [result[key]]
            else:
                vals = []

            # iterate vals
            for v in vals:
                if isinstance(v, basestring) and v:
                    # escape slashes
                    v = v.replace('\\', '\\\\')
                    # escape quotes
                    v = v.replace('"', '\\"')
                elif isinstance(v, basestring) and len(vals) == 1:
                    continue

                # check map
                if mapexp(key):
                    _raw += ', %s="%s"' % ('orig_' + key.lstrip('_'), v)
                else:
                    _raw += ', %s="%s"' % (key, v)

        return _raw

    def addevent(self, raw, sourcetype, cam_header=True):
        """ The purpose of this method is to add a properly constructed event
        to the events list in the ModularAction instance.  This ensures events
        are created with the appropriate index-time header.

        The index-time header is responsible for setting sourcetype,
        orig_action_name, orig_sid, and orig_rid.  The index-time header will
        not be present in the _raw of generated events.

        Remember to call update() prior to addevent() to ensure that the events
        reflect the appropriate orig_sid and orig_rid identifiers.

        @param raw:        The text of the event you want to generate.
        @param sourcetype: The sourcetype of the event you want to generate.
        @param cam_header: Optionally exclude the inclusion of the index-time header.
                           Defaults to True (include header).
        """
        if cam_header:
            if self.orig_sid:
                action_idline = self.DEFAULT_IDLINE % (
                    self.get_header_item(
                        'orig_action_name', self.action_name, 'unknown'),
                    self.get_header_item('orig_sid', self.orig_sid),
                    self.get_header_item('orig_rid', self.orig_rid),
                    self.get_header_item('sourcetype', sourcetype))
            else:
                action_idline = self.DEFAULT_IDLINE % (
                    self.get_header_item(
                        'orig_action_name', self.action_name, 'unknown'),
                    self.get_header_item('orig_sid', self.sid),
                    self.get_header_item('orig_rid', self.rid),
                    self.get_header_item('sourcetype', sourcetype))
            self.events.append(action_idline.rstrip() + '\n' + raw)
        else:
            self.events.append(raw)

    def writeevents(self, index='summary', host=None, source=None, fext='common_action_model'):
        """ The purpose of this method is to create arbitrary splunk events
        from the list of events in the ModularAction instance.

        Please use addevent() for populating the list of events in
        the ModularAction instance.

        @param index:  The index to write the events to.
                       Defaults to "summary".
        @param host:   The value of host the events should take on.
                       Defaults to None (auto).
        @param source: The value of source the events should take on.
                       Defaults to None (auto).
        @param fext:   The extension of the file to write out.
                       Files are written to $SPLUNK_HOME/var/spool/splunk.
                       File extensions can only contain word characters,
                       dash, and have a 200 char max.
                       "stash_" is automatically prepended to all extensions.
                       Defaults to "common_action_model" ("stash_common_action_model").
                       Only override if you've set up a corresponding props.conf
                       stanza to handle the extension.

        @return bool:  Returns True if all events were successfully written
                       Returns False if any errors were encountered
        """
        if self.events:
            # sanitize file extension
            if not fext or not re.match(r'^[\w-]+$', fext):
                self.logger.warn('Requested file extension was ignored due to invalid characters')
                fext = 'common_action_model'
            elif len(fext) > 200:
                self.logger.warn('Requested file extension was ignored due to length')
                fext = 'common_action_model'
            # header
            header_line = self.DEFAULT_HEADER % (
                self.get_header_item('index', index, self.DEFAULT_INDEX),
                self.get_header_item('host', host),
                self.get_header_item('source', source))
            header_line = header_line.rstrip()
            # process event chunks
            for chunk in (
                    self.events[x:x + self.DEFAULT_CHUNK]
                    for x in range(0, len(self.events), self.DEFAULT_CHUNK)):
                # initialize output string
                default_breaker = '\n' + self.DEFAULT_BREAKER
                fout = header_line + default_breaker + (default_breaker).join(chunk)
                # write output string
                try:
                    fn = '{0}_{1}.stash_{2}'.format(
                        mktimegm(time.gmtime()),
                        random.randint(0, 100000),
                        fext)
                    fp = make_splunkhome_path(['var', 'spool', 'splunk', fn])
                    # obtain fh
                    with open(fp, 'w') as fh:
                        fh.write(fout)
                except Exception:
                    signature = 'Error obtaining file handle during makeevents'
                    self.message(signature, level=logging.ERROR, file_path=fp)
                    self.logger.exception(signature + ' file_path=%s' % fp)
                    return False
            self.message(
                'Successfully created splunk events',
                event_count=len(self.events)
            )
            return True
        return False

    def validate(self):
        """ This method serves as an illustration stub.
        Serves as a container for operations which validate the action's parameters.

        Outer Validation - validation based on non-result based arguments (i.e. user input).
        Inner Validation - validation based on result based key-values

        Since validate() (both inner and outer validation) will be called after
        update()/invoke() and prior to dowork(), it will be important to ensure that
        one-time validation (i.e. outer validation) is only done once.  Consider
        using len(rids)<=1.

        For cleanliness it is recommended that you subclass ModularAction
        and implement your own validate() method.
        """
        return

    def queuework(self, exit_strategy=None, tries=3, raise_all=False):
        """ This method will queue an action (instead of performing it)
        by inserting a row into the cam_queue kvstore collection

        For action authors wanting to support remote workers it is important
        that this method be called immediately after class initialization
        and prior to processing results_file and calling dowork().

        Whether or not queuework() returns or exits is determined by exit_strategy
        which can be specified explicitly or determined dynamically based on
        the list of _cam_workers.  For instance, if exit_strategy is None and
        "local" is present in _cam_worker, queuework() will return (not exit).

        @param exit_strategy:
            Whether or not queuework should exit the script
            None (dynamic), True, False

        @param tries:
            The number of times to try the queue operation

        @param raise_all:
            Whether or not to raise certain exceptions we would
            normally WARN for.
        """
        # 1. Load the common action model.
        # If we can't load _cam, "continue" unless raise_all=True
        try:
            _cam = json.loads(self.configuration.get('_cam') or '{}')
        except Exception:
            signature = 'Failed to load _cam'
            if raise_all:
                raise Exception(signature)
            else:
                self.message(signature, level=logging.WARN)
                return

        # 2. Determine if the action supports workers.
        # If it does not; return.
        supports_workers = normalizeBoolean(
            _cam.get('supports_workers', False))

        # the lack of worker support is not a "raisable" offense
        # action_name must be valid as well
        if (supports_workers is not True
                or not self.action_name
                or self.action_name == 'unknown'):
            self.message(
                'Action does not support workers',
                level=logging.WARN
            )
            return

        # 3. Load _cam_workers (workers list).
        # If we can't load _cam_workers, "continue" unless raise_all=True
        try:
            _cam_workers = list(set(
                json.loads(self.configuration.get('_cam_workers') or '[]')
            ))
        except Exception:
            signature = 'Failed to load _cam_workers'
            if raise_all:
                raise Exception(signature)
            else:
                self.message(signature, level=logging.WARN)
                return

        # 4. Determine if queuework will exit or keep going
        # If exit is None, determine exit based on _cam_workers (dynamically)
        exit_strategy = normalizeBoolean(exit_strategy)

        # if exit_strategy is None and work to be done locally
        if (exit_strategy is None
                and ('local' in _cam_workers)):
            exit_strategy = False
        # if exit_strategy is None and work not to be done locally
        elif exit_strategy is None:
            exit_strategy = True
        # if exit_strategy is True, take at face value
        elif exit_strategy is True:
            pass
        # otherwise exit_strategy is False
        else:
            exit_strategy = False

        self.logger.debug('exit_strategy={0}'.format(exit_strategy))

        # Remove local
        _cam_workers = sorted(list(
            set(_cam_workers) - set(['local'])
        ))

        # If no workers or local-only workers; return
        if not _cam_workers:
            self.message('No workers specified')
            return

        # use unaltered sid from payload
        sid = str(self.settings.get('sid'))

        # 5. Get info
        info = ''
        info_data = self.addinfo()
        info = base64.b64encode(info_data.encode('utf-8')).decode('utf-8')

        # 6. Queue action
        records = []
        record = {
            'time': mktimegm(time.gmtime()),
            'action_name': self.action_name,
            'sid': sid,
            'info': info,
            'settings': json.dumps(self.settings)
        }

        for worker in _cam_workers:
            new_record = record.copy()
            new_record['worker'] = worker
            records.append(new_record)

        c = None
        for unused_x in range(0, tries):
            try:
                r, c = rest.simpleRequest(
                    self.CAM_QUEUE_URI,
                    sessionKey=self.session_key,
                    jsonargs=json.dumps(records)
                )
                c = c.decode('utf-8')

                if r.status == http_client.OK:
                    # generate pending messages on behalf
                    # of each worker
                    for worker in _cam_workers:
                        self.message(
                            'Successfully queued action',
                            status='pending',
                            worker=worker
                        )
                    if exit_strategy:
                        sys.exit(0)
                    else:
                        break

            except Exception as e:
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.exception(e)

        else:
            if exit_strategy:
                if c is not None:
                    raise Exception(c)
                else:
                    raise e  # noqa: F821
            else:
                if c is not None:
                    self.logger.error(c)
                # if we're in debug don't keep barking
                elif not self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.error(e)  # noqa: F821

                for worker in _cam_workers:
                    self.message(
                        'Unable to queue action',
                        status='failure',
                        worker=worker
                    )

    def dowork(self):
        """ This method serves as an illustration stub.
        Serves as a container for operations which satisfy the nature of the action.
        For instance, the third party API call.

        For cleanliness it is recommended that you subclass ModularAction
        and implement your own dowork() method.
        """
        return

    @staticmethod
    def setup_logger(
            name,
            level=logging.INFO,
            maxBytes=25000000,
            backupCount=5,
            format=SHORT_FORMAT):
        """ Set up a logging instance.

        @param name:        The log file name.
                            We recommend "$action_name$_modalert".
        @param level:       The logging level.
        @param maxBytes:    The maximum log file size before rollover.
        @param backupCount: The number of log files to retain.

        @return logger:     Returns an instance of logger
        """
        logfile = make_splunkhome_path(['var', 'log', 'splunk', name + '.log'])
        logger = logging.getLogger(name)
        logger.setLevel(level)
        # Prevent the log messages from being duplicated in the python.log file
        logger.propagate = False

        # Prevent re-adding handlers to the logger object, which can cause duplicate log lines.
        handler_exists = any([True for h in logger.handlers if h.baseFilename == logfile])
        if not handler_exists:
            file_handler = logging.handlers.RotatingFileHandler(
                logfile, maxBytes=maxBytes, backupCount=backupCount, delay=True)
            ModularActionFormatter.converter = time.gmtime
            formatter = ModularActionFormatter(format)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger

    @staticmethod
    # internal makeevents method for normalizing strings
    # that will be used in the various headers we write out
    def get_header_item(field, value, default=None):
        """This method is used to normalize strings destined for
        index-time headers.

        @param field:   The field name (string)
        @param value:   The value (string)
        @param default: The default (string); defaults to None

        @return string: If value; the field="value" pair
                        Else; empty string
        """
        value = value or default
        if field and value:
            try:
                return '%s="%s"' % (field, value.replace('"', '_'))
            except AttributeError:
                pass
        return ''


class ModularActionTimer(object):
    """ The purpose of this method is to log execution times for different code paths
    within a modular action script.  When the majority of the script is wrapped, this can
    be used to log the approximate run duration of the action script.

    Example:

    with ModularActionTimer(modaction, 'main') as t:
        <whatever block of codes>
    (optionally do something with t.interval)

    @param modaction: A modular action class instance instance.
    @param component: The component of the action script for which interval is measured.
    @param start:     Optional. Floating point representation of the start timer.
                      Defaults to entry timer.
    """

    def __init__(self, modaction, component, start=None):
        self.modaction = modaction
        self.component = component
        self.start = start
        self.interval = -1

    def __enter__(self):
        self.start = self.start or timer()
        return self

    def __exit__(self, *args):
        try:
            self.interval = int((timer() - self.start) * 1000)
            self.modaction.message(
                'Modular action script duration',
                component=self.component,
                duration=self.interval
            )
        except Exception:
            self.modaction.message(
                'Unable to compute duration',
                level=logging.WARN
            )
