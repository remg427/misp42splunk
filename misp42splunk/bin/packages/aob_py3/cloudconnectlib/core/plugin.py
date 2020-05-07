from __future__ import absolute_import
from builtins import next
from .ext import _extension_functions
from os import path as op
from os import walk
import sys
from ..common import log
import traceback
import importlib

logger = log.get_cc_logger()


def cce_pipeline_plugin(func):
    """
    Decorator for pipepline plugin functions.

    This docorator helps to register user defined pipeline function into CCE
    engine so that it could be looked up when executing jobs.

    :param func: User defined function object
    :type func: ``function``

    Usage::
        >>> @cce_pipeline_plugin
        >>> def my_function(arg):
        >>>     do_work()
    """
    if not callable(func):
        logger.debug("Function %s is not callable, don't add it as a pipeline"
                     " function", func.__name__)
    else:
        if func.__name__ in list(_extension_functions.keys()):
            logger.warning("Pipeline function %s already exists, please rename"
                           "it!", func.__name__)
        else:
            _extension_functions[func.__name__] = func
            logger.debug("Added function %s to pipeline plugin system",
                        func.__name__)

    def pipeline_func(*args, **kwargs):
        return func(*args, **kwargs)
    return pipeline_func


def import_plugin_file(file_name):
    """
    Import a module.
    1. If the module with the same name already in sys.modules, then log a
    warning and exit without reloading it.
    2. If failed to import the file, then log a warning and exit
    """
    if file_name.endswith(".py"):
        module_name = file_name[:-3]
    else:
        logger.warning("Plugin file %s is with unsupported extenstion, the "
                       "supported are py", file_name)
        return

    if module_name in list(sys.modules.keys()):
        logger.warning("Module %s aleady exists and it won't be reload, "
                       "please rename your plugin module if it is required.",
                       module_name)
        return

    try:
        importlib.import_module(module_name)
    except Exception:
        logger.warning("Failed to load module {}, {}".format(
            module_name, traceback.format_exc()))
        return

    logger.info("Module %s is imported", module_name)
    return


def init_pipeline_plugins(plugin_dir):
    """
    Initialize the pipeline plugins which triggers the auto registering of user
    defined pipeline functions.
    1. Add the plugin_dir into sys.path.
    2. Import the file under plugin_dir that starts with "cce_plugin_" and ends
    with ".py"
    """
    if not op.isdir(plugin_dir):
        logger.warning("%s is not a directory! Pipeline plugin files won't be loaded.",
                       plugin_dir)
        return

    sys.path.append(plugin_dir)
    for file_name in next(walk(plugin_dir))[2]:
        if file_name == "__init__.py" or not file_name.startswith("cce_plugin_"):
            continue
        if file_name.endswith(".py"):
            import_plugin_file(file_name)
