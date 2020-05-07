"""APP Cloud Connect errors"""


class CCEError(Exception):
    pass


class ConfigException(CCEError):
    """Config exception"""
    pass


class FuncException(CCEError):
    """Ext function call exception"""
    pass


class HTTPError(CCEError):
    """ HTTPError raised when HTTP request returned a error."""

    def __init__(self, reason=None):
        """
        Initialize HTTPError with `response` object and `status`.
        """
        self.reason = reason
        super(HTTPError, self).__init__(reason)


class StopCCEIteration(CCEError):
    """Exception to exit from the engine iteration."""
    pass


class CCESplitError(CCEError):
    """Exception to exit the job in Split Task"""
    pass


class QuitJobError(CCEError):
    pass
