from builtins import object
import copy
import threading
from abc import abstractmethod
import six

from cloudconnectlib.common.log import get_cc_logger
from cloudconnectlib.core import defaults
from cloudconnectlib.core.checkpoint import CheckpointManagerAdapter
from cloudconnectlib.core.exceptions import HTTPError
from cloudconnectlib.core.exceptions import StopCCEIteration, CCESplitError
from cloudconnectlib.core.ext import lookup_method
from cloudconnectlib.core.http import get_proxy_info, HttpClient
from cloudconnectlib.core.models import DictToken, _Token, BasicAuthorization, Request

logger = get_cc_logger()

_RESPONSE_KEY = '__response__'
_AUTH_TYPES = {
    'basic_auth': BasicAuthorization
}


class ProcessHandler(object):
    def __init__(self, method, arguments, output):
        self.method = method
        self.arguments = [_Token(arg) for arg in arguments or ()]
        self.output = output

    def execute(self, context):
        args = [arg.render(context) for arg in self.arguments]
        logger.debug('%s arguments found for method %s', len(args), self.method)
        callable_method = lookup_method(self.method)
        result = callable_method(*args)

        data = {}
        if self.output:
            data[self.output] = result

        return data


class Condition(object):
    def __init__(self, method, arguments):
        self.method = method
        self.arguments = [_Token(arg) for arg in arguments or ()]

    def is_meet(self, context):
        args = [arg.render(context) for arg in self.arguments]
        callable_method = lookup_method(self.method)
        logger.debug('%s arguments found for method %s', len(args), self.method)
        return callable_method(*args)


class ConditionGroup(object):
    def __init__(self):
        self._conditions = []

    def add(self, condition):
        self._conditions.append(condition)

    def is_meet(self, context):
        return any(
            cdn.is_meet(context) for cdn in self._conditions
        )


class ProxyTemplate(object):
    def __init__(self, proxy_setting):
        self._proxy = DictToken(proxy_setting or {})

    def render(self, context):
        rendered = self._proxy.render(context)
        return get_proxy_info(rendered)


class RequestTemplate(object):
    def __init__(self, request):
        if not request:
            raise ValueError('The request is none')
        url = request.get('url')
        if not url:
            raise ValueError("The request doesn't contain a url or it's empty")
        self.url = _Token(url)
        self.nextpage_url = _Token(request.get('nextpage_url', url))
        self.headers = DictToken(request.get('headers', {}))

        # Request body could be string or dict
        body = request.get('body')
        if isinstance(body, dict):
            self.body = DictToken(body)
        elif isinstance(body, six.string_types):
            self.body = _Token(body)
        else:
            if body:
                logger.warning('Invalid request body: %s', body)
            self.body = None

        method = request.get('method', 'GET')
        if not method or method.upper() not in ('GET', 'POST'):
            raise ValueError('Unsupported value for request method: {}'.format(method))
        self.method = _Token(method)

        self.count = 0

    def reset(self):
        self.count = 0

    def render(self, context):
        if self.count == 0 or not self.nextpage_url:
            url = self.url.render(context)
        else:
            url = self.nextpage_url.render(context)

        self.count += 1
        return Request(
            url=url,
            method=self.method.render(context),
            headers=self.headers.render(context),
            body=self.body.render(context) if self.body else None
        )


class BaseTask(object):
    def __init__(self, name):
        self._name = name
        self._pre_process_handler = []
        self._post_process_handler = []
        self._skip_pre_conditions = ConditionGroup()
        self._skip_post_conditions = ConditionGroup()

    def add_preprocess_handler(self, method, input, output=None):
        """
        Add a preprocess handler. All handlers will be maintained and
        executed sequentially.
        :param method: The method name.
        :type method: ``string``
        :param input: The input of the method.
        :type input: ``list``
        :param output: The output variable name.
        :type output: ``string``
        """
        handler = ProcessHandler(method, input, output)
        self._pre_process_handler.append(handler)

    def add_preprocess_skip_condition(self, method, input):
        """
        Add a preprocess skip condition. The skip_conditions for preprocess
        defines a group of conditions and the relation of them is OR which
        means if any one of them returns True then the whole skip_conditions
        returns True. If it returns True, then the preprocess pipeline will
         be skipped.
        :param method: The method name.
        :type method: ``string``
        :param input: The input of the method.
        :type input: ``list``
        """
        self._skip_pre_conditions.add(Condition(method, input))

    def add_postprocess_handler(self, method, input, output=None):
        """
        Add a postprocess handler. All handlers will be maintained and
        executed sequentially.
        :param method: The method name.
        :type method: ``string``
        :param input: The input of the method.
        :type input: ``list``
        :param output: The output variable name.
        :type output: ``string``
        """
        handler = ProcessHandler(method, input, output)
        self._post_process_handler.append(handler)

    def add_postprocess_skip_condition(self, method, input):
        """
        Add a preprocess skip condition. The skip_conditions for postprocess
        defines a group of conditions and the relation of them is OR which means
         if any one of them returns True then the whole skip_conditions returns
          True. If it returns True, then the postprocess pipeline will be skipped.

        :param method: The method name.
        :type method: ``string``
        :param input: The input of the method.
        :type input: ``list``
        """
        self._skip_post_conditions.add(Condition(method, input))

    @staticmethod
    def _execute_handlers(skip_conditions, handlers, context, phase):
        if skip_conditions.is_meet(context):
            logger.debug('%s process skip conditions are met', phase.capitalize())
            return
        if not handlers:
            logger.debug('No handler found in %s process', phase)
            return

        for handler in handlers:
            data = handler.execute(context)
            if data:
                # FIXME
                context.update(data)
        logger.debug('Execute handlers finished successfully.')

    def _pre_process(self, context):
        self._execute_handlers(self._skip_pre_conditions,
                               self._pre_process_handler,
                               context,
                               'pre')

    def _post_process(self, context):
        self._execute_handlers(self._skip_post_conditions,
                               self._post_process_handler,
                               context,
                               'post')

    @abstractmethod
    def perform(self, context):
        pass

    def stop(self, block=False, timeout=30):
        pass

    def __str__(self):
        return self._name

    def __repr__(self):
        return self.__str__()


class CCESplitTask(BaseTask):
    OUTPUT_KEY = "__cce_split_result__"

    def __init__(self, name):
        super(CCESplitTask, self).__init__(name)
        self._process_handler = None
        self._source = None

    def configure_split(self, method, source, output, separator=None):
        arguments = [source, output, separator]
        self._source = source
        self._process_handler = ProcessHandler(method, arguments,
                                               CCESplitTask.OUTPUT_KEY)

    def perform(self, context):
        logger.debug('Task=%s start to run', self)
        try:
            self._pre_process(context)
        except StopCCEIteration:
            logger.info('Task=%s exits in pre_process stage', self)
            yield context
            return

        if not self._process_handler:
            logger.info('Task=%s has no split method', self)
            raise CCESplitError

        try:
            invoke_results = self._process_handler.execute(context)
        except:
            logger.exception("Task=%s encountered exception", self)
            raise CCESplitError
        if not invoke_results or not \
                invoke_results.get(CCESplitTask.OUTPUT_KEY):
            raise CCESplitError
        for invoke_result in invoke_results[CCESplitTask.OUTPUT_KEY]:
            new_context = copy.deepcopy(context)
            new_context.update(invoke_result)
            yield new_context

        logger.debug('Task=%s finished', self)


class CCEHTTPRequestTask(BaseTask):
    """
    CCEHTTPTask represents a HTTP request's properties and its methods.
    It can configure all properties covered by request JSON schema,
     like url, method, auth, pre-process, post-process, skip conditions etc.
    All properties could contain jinja2 template which will be render
     from context when executing.
    """

    def __init__(self, request, name, meta_config=None, task_config=None):
        super(CCEHTTPRequestTask, self).__init__(name)
        self._request = RequestTemplate(request)
        self._stop_conditions = ConditionGroup()
        self._proxy_info = None
        self._max_iteration_count = defaults.max_iteration_count

        self._checkpointer = None
        self._task_config = task_config
        self._meta_config = meta_config

        self._authorizer = None
        self._stopped = threading.Event()
        self._stop_signal_received = False

    def stop(self, block=False, timeout=30):
        """
        Stop current task.
        """
        if self._stopped.is_set():
            logger.info('Task=%s is not running, cannot stop it.', self)
            return
        self._stop_signal_received = True

        if not block:
            return

        if not self._stopped.wait(timeout):
            logger.info('Waiting for stop task %s timeout', self)

    def _check_if_stop_needed(self):
        if self._stop_signal_received:
            logger.info('Stop task signal received, stopping task %s.', self)
            self._stopped.set()
            return True
        return False

    def set_proxy(self, proxy_setting):
        """
        Setup the proxy setting.

        :param proxy_setting: Proxy setting should include the following fields
            "proxy_enabled": ,
            "proxy_url":,
            "proxy_port": ,
            "proxy_username": ,
            "proxy_password": ,
            "proxy_rdns": ,
            "proxy_type": ,
        :type proxy_setting: ``dict``
        """
        self._proxy_info = ProxyTemplate(proxy_setting)

    def set_auth(self, auth_type, settings):
        """
        Set the authentication of HTTP request.
        :param auth_type: Authentication type.
        :type auth_type: ``string``
        :param settings: The detail setting of authentication. It
        could contain jinja2
         template. For example:
            {"username": xxx, "password": xxx}
        :type settings: ``dict``
        """
        if not auth_type:
            raise ValueError('Invalid auth type={}'.format(auth_type))
        authorizer_cls = _AUTH_TYPES.get(auth_type.lower())
        if not authorizer_cls:
            raise ValueError('Unsupported auth type={}'.format(auth_type))
        self._authorizer = authorizer_cls(settings)

    def set_iteration_count(self, count):
        """
        Set the maximum loop count for the request. The request will ignore
         this field if it's less or equal to 0 and will not stopped until
          the stop conditions satisfied. Otherwise if the request count
          reaches the iteration_count, the request will stop.
        :param count: Iteration count.
        :type count: ``integer``
        """
        try:
            self._max_iteration_count = int(count)
        except ValueError:
            self._max_iteration_count = defaults.max_iteration_count
            logger.warning(
                'Invalid iteration count: %s, using default max iteration count: %s',
                count, self._max_iteration_count)

    def add_stop_condition(self, method, input):
        """
        Add a stop condition. The stop_conditions is a group of conditions
         which defines when the request loop should be stopped and the
         relation of them is OR which means if any one of them returns
         True, then the whole skip_conditions returns True. If it
         returns True, then stop looping the request.
        :param method: The method name.
        :type method: ``string``
        :param input: The input of the method.
        :type input: ``list``
        """
        self._stop_conditions.add(Condition(method, input))

    def configure_checkpoint(self, name, content):
        """
        :param name: The checkpoint name.
        :type name: ``string``
        :param content: The checkpoint content.
        :type content: ``dict``
        """
        if not name or not name.strip():
            raise ValueError('Invalid checkpoint name: "{}"'.format(name))
        if not content:
            raise ValueError('Invalid checkpoint content: {}'.format(content))
        self._checkpointer = CheckpointManagerAdapter(
            namespaces=name,
            content=content,
            meta_config=self._meta_config,
            task_config=self._task_config
        )

    def _should_exit(self, done_count, context):
        if 0 < self._max_iteration_count <= done_count:
            logger.info('Iteration count reached %s', self._max_iteration_count)
            return True

        if self._stop_conditions.is_meet(context):
            logger.info('Stop conditions are met')
            return True
        return False

    @staticmethod
    def _send_request(client, request):
        try:
            response = client.send(request)
        except HTTPError as error:
            logger.exception(
                'Error occurred in request url=%s method=%s reason=%s',
                request.url, request.method, error.reason
            )
            return None, True

        status = response.status_code

        if status in defaults.success_statuses:
            if not (response.body or '').strip():
                logger.info(
                    'The response body of request which url=%s and'
                    ' method=%s is empty, status=%s.',
                    request.url, request.method, status
                )
                return None, True
            return response, False

        error_log = ('The response status=%s for request which url=%s and'
                     ' method=%s.') % (
                        status, request.url, request.method
                    )

        if status in defaults.warning_statuses:
            logger.warning(error_log)
        else:
            logger.error(error_log)

        return response, True

    def _persist_checkpoint(self, context):
        if not self._checkpointer:
            logger.debug('Checkpoint is not configured. Skip persisting checkpoint.')
            return
        try:
            self._checkpointer.save(context)
        except Exception:
            logger.exception('Error while persisting checkpoint')
        else:
            logger.debug('Checkpoint has been updated successfully.')

    def _load_checkpoint(self, ctx):
        if not self._checkpointer:
            logger.debug('Checkpoint is not configured. Skip loading checkpoint.')
            return {}
        return self._checkpointer.load(ctx=ctx)

    def _prepare_http_client(self, ctx):
        proxy = self._proxy_info.render(ctx) if self._proxy_info else None
        return HttpClient(proxy)

    def perform(self, context):
        logger.info('Starting to perform task=%s', self)

        client = self._prepare_http_client(context)
        done_count = 0

        context.update(self._load_checkpoint(context))
        update_source = False if context.get('source') else True
        self._request.reset()

        while True:
            try:
                self._pre_process(context)
            except StopCCEIteration:
                logger.info("Task=%s exits in pre_process stage", self)
                break

            if self._check_if_stop_needed():
                break

            r = self._request.render(context)
            if self._authorizer:
                self._authorizer(r.headers, context)

            response, need_exit = self._send_request(client, r)
            context[_RESPONSE_KEY] = response

            if need_exit:
                logger.info('Task=%s need been terminated due to request response', self)
                break
            if self._check_if_stop_needed():
                break

            if update_source:
                context['source'] = r.url.split('?')[0]

            try:
                self._post_process(context)
            except StopCCEIteration:
                logger.info("Task=%s exits in post_process stage", self)
                break

            self._persist_checkpoint(context)

            if self._check_if_stop_needed():
                break

            done_count += 1
            if self._should_exit(done_count, context):
                break
        if update_source and context.get('source'):
            del context['source']
        yield context

        self._stopped.set()
        if self._checkpointer:
            # Flush checkpoint cache to disk
            self._checkpointer.close()
        logger.info('Perform task=%s finished', self)
