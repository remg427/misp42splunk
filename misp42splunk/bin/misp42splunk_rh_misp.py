
import misp42splunk_declare


from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    DataInputModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunk_aoblib.rest_migration import ConfigMigrationHandler
import os
import shutil

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        'misp_url',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.Pattern(
            regex=r"""^https:\/\/[0-9a-zA-Z\-\.]+(?:\:\d+)?""",
        )
    ),
    field.RestField(
        'misp_key',
        required=True,
        encrypted=True,
        default=None,
        validator=validator.String(
            max_len=8192,
            min_len=0,
        )
    ),
    field.RestField(
        'misp_verifycert',
        required=False,
        encrypted=False,
        default=True,
        validator=None
    ),
    field.RestField(
        'misp_ca_full_path',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=8192,
            min_len=0,
        )
    ),
    field.RestField(
        'misp_use_proxy',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ),
    field.RestField(
        'client_use_cert',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ),
    field.RestField(
        'client_cert_full_path',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=8192,
            min_len=0,
        )
    ),

    field.RestField(
        'disabled',
        required=False,
        validator=None
    )

]
model = RestModel(fields, name=None)


endpoint = DataInputModel(
    'misp',
    model,
)


if __name__ == '__main__':
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    app_name = "misp42splunk"
    local_dir= os.path.join(
        _SPLUNK_PATH, 'etc', 'apps',
        app_name,
        'local'
    )
    inputs_conf_file = os.path.join(local_dir, 'inputs.conf')
    misp_instances_file = os.path.join(local_dir, 'misp42splunk_instances.conf')
    if os.path.exists(misp_instances_file):
        shutil.copy(misp_instances_file, inputs_conf_file)
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
    shutil.copy(inputs_conf_file, misp_instances_file)
