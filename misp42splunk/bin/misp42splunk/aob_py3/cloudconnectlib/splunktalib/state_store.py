from builtins import object
import json
import os
import os.path as op
import time
import traceback
from abc import abstractmethod

from ..splunktacollectorlib.common import log as stulog
from ..splunktalib import kv_client as kvc
from ..splunktalib.common import util


def get_state_store(meta_configs,
                    appname,
                    collection_name="talib_states",
                    use_kv_store=False,
                    use_cache_file=True,
                    max_cache_seconds=5):
    if util.is_true(use_kv_store):
        # KV store based checkpoint
        return StateStore(appname, meta_configs['server_uri'], meta_configs['session_key'], collection_name)
    checkpoint_dir = meta_configs['checkpoint_dir']
    if util.is_true(use_cache_file):
        return CachedFileStateStore(appname, checkpoint_dir, max_cache_seconds)
    return FileStateStore(appname, checkpoint_dir)


class BaseStateStore(object):
    def __init__(self, app_name):
        self._app_name = app_name

    @abstractmethod
    def update_state(self, key, states):
        pass

    @abstractmethod
    def get_state(self, key):
        pass

    @abstractmethod
    def delete_state(self, key):
        pass

    def close(self, key=None):
        pass


class StateStore(BaseStateStore):
    def __init__(self, app_name, server_uri, session_key, collection_name="talib_states"):
        """
        :meta_configs: dict like and contains checkpoint_dir, session_key,
         server_uri etc
        :app_name: the name of the app
        :collection_name: the collection name to be used.
        Don"t use other method to visit the collection if you are using
         StateStore to visit it.
        """
        super(StateStore, self).__init__(app_name)

        # State cache is a dict from _key to value
        self._states_cache = {}
        self._kv_client = None
        self._collection = collection_name
        self._kv_client = kvc.KVClient(
            splunkd_host=server_uri,
            session_key=session_key
        )
        kvc.create_collection(self._kv_client, self._collection, self._app_name)
        self._load_states_cache()

    def update_state(self, key, states):
        """
        :state: Any JSON serializable
        :return: None if successful, otherwise throws exception
        """

        data = {'value': json.dumps(states)}

        if key not in self._states_cache:
            data['_key'] = key
            self._kv_client.insert_collection_data(
                collection=self._collection, data=data, app=self._app_name
            )
        else:
            self._kv_client.update_collection_data(
                collection=self._collection, key_id=key, data=data, app=self._app_name
            )
        self._states_cache[key] = states

    def get_state(self, key=None):
        if key:
            return self._states_cache.get(key, None)
        return self._states_cache

    def delete_state(self, key=None):
        if key:
            self._delete_state(key)
        else:
            for key in list(self._states_cache.keys()):
                self._delete_state(key)

    def _delete_state(self, key):
        if key not in self._states_cache:
            return

        self._kv_client.delete_collection_data(
            self._collection, key, self._app_name)
        del self._states_cache[key]

    def _load_states_cache(self):
        states = self._kv_client.get_collection_data(
            self._collection, None, self._app_name)
        if not states:
            return

        for state in states:
            value = state['value'] if 'value' in state else state
            key = state['_key']
            try:
                value = json.loads(value)
            except Exception:
                stulog.logger.warning(
                    'Unable to load state from cache, key=%s, error=%s',
                    key, traceback.format_exc())
                pass

            self._states_cache[key] = value


def _create_checkpoint_dir_if_needed(checkpoint_dir):
    if os.path.isdir(checkpoint_dir):
        return

    stulog.logger.info(
        "Checkpoint dir '%s' doesn't exist, try to create it",
        checkpoint_dir)
    try:
        os.mkdir(checkpoint_dir)
    except OSError:
        stulog.logger.exception(
            "Failure creating checkpoint dir '%s'", checkpoint_dir
        )
        raise Exception(
            "Unable to create checkpoint dir '{}'".format(checkpoint_dir)
        )


class FileStateStore(BaseStateStore):
    def __init__(self, app_name, checkpoint_dir):
        super(FileStateStore, self).__init__(app_name)
        self._checkpoint_dir = checkpoint_dir

    def _get_checkpoint_file(self, filename):
        return op.join(self._checkpoint_dir, filename)

    @staticmethod
    def _remove_if_exist(filename):
        if op.exists(filename):
            os.remove(filename)

    def update_state(self, key, states):
        """
        :state: Any JSON serializable
        :return: None if successful, otherwise throws exception
        """

        _create_checkpoint_dir_if_needed(self._checkpoint_dir)

        filename = self._get_checkpoint_file(key)
        with open(filename + ".new", "w") as json_file:
            json.dump(states, json_file)

        self._remove_if_exist(filename)

        os.rename(filename + ".new", filename)

    def get_state(self, key):
        filename = self._get_checkpoint_file(key)
        if op.exists(filename):
            with open(filename) as json_file:
                state = json.load(json_file)
                return state
        else:
            return None

    def delete_state(self, key):
        self._remove_if_exist(self._get_checkpoint_file(key))


class CachedFileStateStore(FileStateStore):
    def __init__(self, app_name, checkpoint_dir, max_cache_seconds=5):
        """
        :meta_configs: dict like and contains checkpoint_dir, session_key,
        server_uri etc
        """

        super(CachedFileStateStore, self).__init__(app_name, checkpoint_dir)
        self._states_cache = {}  # item: time, dict
        self._states_cache_lmd = {}  # item: time, dict
        self.max_cache_seconds = max_cache_seconds

    def update_state(self, key, states):
        now = time.time()
        if key in self._states_cache:
            last = self._states_cache_lmd[key][0]
            if now - last >= self.max_cache_seconds:
                self._update_and_flush_state(now, key, states)
        else:
            self._update_and_flush_state(now, key, states)
        self._states_cache[key] = (now, states)

    def _update_and_flush_state(self, now, key, states):
        """
        :state: Any JSON serializable
        :return: None if successful, otherwise throws exception
        """
        self._states_cache_lmd[key] = (now, states)
        super(CachedFileStateStore, self).update_state(key, states)

    def get_state(self, key):
        if key in self._states_cache:
            return self._states_cache[key][1]

        filename = self._get_checkpoint_file(key)

        if op.exists(filename):
            with open(filename) as json_file:
                state = json.load(json_file)
                now = time.time()
                self._states_cache[key] = now, state
                self._states_cache_lmd[key] = now, state
                return state
        else:
            return None

    def delete_state(self, key):
        super(CachedFileStateStore, self).delete_state(key)

        if self._states_cache.get(key):
            del self._states_cache[key]
        if self._states_cache_lmd.get(key):
            del self._states_cache_lmd[key]

    def close(self, key=None):
        if not key:
            for k, (t, s) in self._states_cache.items():
                self._update_and_flush_state(t, k, s)
            self._states_cache.clear()
            self._states_cache_lmd.clear()
        elif key in self._states_cache:
            self._update_and_flush_state(self._states_cache[key][0], key,
                                         self._states_cache[key][1])
            del self._states_cache[key]
            del self._states_cache_lmd[key]
