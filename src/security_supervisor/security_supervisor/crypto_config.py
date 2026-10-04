"""Builds the SecureChannel (or NullChannel) each node uses.

Split out from crypto_channel.py so that module stays pure crypto with no
file/YAML concerns and can be unit tested without a config on disk.
"""
import os
from typing import Optional

import yaml

from security_supervisor.crypto_channel import (
    NullChannel,
    SecureChannel,
    load_root_key,
)

DEFAULT_CONFIG_PATH = os.path.expanduser('~/uav_security_ws/config/security_config.yaml')


def load_crypto_config(path: Optional[str] = None) -> dict:
    path = path or DEFAULT_CONFIG_PATH
    try:
        with open(os.path.expanduser(path), 'r') as handle:
            cfg = yaml.safe_load(handle) or {}
    except FileNotFoundError:
        return {'enabled': False, 'key_file': None, 'drop_replayed': False,
                'events_rate_hz': 0.0, '_missing_config': True}
    crypto = cfg.get('crypto', {}) or {}
    crypto.setdefault('enabled', False)
    crypto.setdefault('key_file', None)
    crypto.setdefault('drop_replayed', False)
    crypto.setdefault('events_rate_hz', 0.0)
    return crypto


def build_channel(sender_id: str, config_path: Optional[str] = None, logger=None):
    """Return (channel, crypto_config).

    A configured-but-unusable key is fatal rather than silently downgraded:
    quietly falling back to plaintext when someone asked for encryption is
    exactly the failure you do not want in a security component.
    """
    cfg = load_crypto_config(config_path)

    if not cfg.get('enabled'):
        if logger:
            logger.warning(
                'crypto DISABLED (security_config.yaml crypto.enabled=false) -- '
                '/security control-plane traffic is in the clear')
        return NullChannel(sender_id), cfg

    root_key = load_root_key(cfg.get('key_file'))
    channel = SecureChannel(root_key, sender_id=sender_id)
    if logger:
        logger.info(
            f'crypto ENABLED (ChaCha20-Poly1305, sender_id={sender_id}, '
            f'epoch={channel.epoch}, drop_replayed={cfg.get("drop_replayed")})')
    return channel, cfg
