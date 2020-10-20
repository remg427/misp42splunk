import logging

from solnlib.pattern import Singleton
from ..splunktacollectorlib.common import log as stulog
from ..splunktacollectorlib.data_collection import ta_helper as th
from .lib_util import get_mod_input_script_name
from future.utils import with_metaclass


class CloudClientLogAdapter(with_metaclass(Singleton, logging.LoggerAdapter)):
    def __init__(self, logger=None, extra=None, prefix=""):
        super(CloudClientLogAdapter, self).__init__(logger, extra)
        self.cc_prefix = prefix if prefix else ""

    def process(self, msg, kwargs):
        msg = "{} {}".format(self.cc_prefix, msg)
        return super(CloudClientLogAdapter, self).process(msg, kwargs)

    def set_level(self, val):
        self.logger.setLevel(val)


_adapter = CloudClientLogAdapter(stulog.logger)


def set_cc_logger(logger, logger_prefix=''):
    global _adapter
    _adapter.logger = logger
    _adapter.cc_prefix = logger_prefix or ''


def get_cc_logger():
    return _adapter


def reset_cc_logger(stanza_name, logging_level, logger_prefix=''):
    script_name = get_mod_input_script_name()
    logger_name = script_name + "_" + th.format_name_for_file(stanza_name)
    stulog.reset_logger(logger_name)
    stulog.set_log_level(logging_level)
    set_cc_logger(stulog.logger, logger_prefix)
    return get_cc_logger()