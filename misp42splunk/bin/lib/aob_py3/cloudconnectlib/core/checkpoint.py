import cloudconnectlib.splunktacollectorlib.data_collection.ta_checkpoint_manager as tacm
from cloudconnectlib.common.log import get_cc_logger
from cloudconnectlib.core.models import _Token, DictToken

logger = get_cc_logger()


class CheckpointManagerAdapter(tacm.TACheckPointMgr):
    """Wrap TACheckPointMgr for custom usage"""

    def __init__(self, namespaces, content, meta_config, task_config):
        super(CheckpointManagerAdapter, self).__init__(meta_config, task_config)
        if isinstance(namespaces, (list, tuple)):
            self.namespaces = (_Token(t) for t in namespaces)
        else:
            self.namespaces = [_Token(namespaces)]
        self.content = DictToken(content)

    def _namespaces_for(self, ctx):
        return [item.render(ctx) for item in self.namespaces]

    def save(self, ctx):
        """Save checkpoint"""
        super(CheckpointManagerAdapter, self).update_ckpt(
            ckpt=self.content.render(ctx),
            namespaces=self._namespaces_for(ctx)
        )

    def load(self, ctx):
        """Load checkpoint"""
        namespaces = self._namespaces_for(ctx)
        checkpoint = super(CheckpointManagerAdapter, self).get_ckpt(namespaces)
        if checkpoint is None:
            logger.info('No existing checkpoint found')
            checkpoint = {}
        return checkpoint
