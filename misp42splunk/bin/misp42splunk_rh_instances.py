
import misp42splunk_declare

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    SingleModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunk_aoblib.rest_migration import ConfigMigrationHandler

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
    )
]
model = RestModel(fields, name=None)


endpoint = SingleModel(
    'misp42splunk_instances',
    model,
)


if __name__ == '__main__':
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
