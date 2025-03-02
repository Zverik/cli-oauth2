"""Tokens storage"""

import json
import logging
import os
from typing import Optional

import keyring
import platformdirs

log = logging.getLogger(__name__)


class BaseStorage:

    @staticmethod
    def _token_key(provider_id: str, client_id: str):
        return f'{provider_id}/{client_id}'

    def load(self):
        raise NotImplementedError()

    def save(self, tokens: dict):
        raise NotImplementedError()

    def get_token(self, provider_id: str, client_id: str):
        return self.load().get(self._token_key(provider_id, client_id))

    def set_token(self, provider_id: str, client_id: str, token: Optional[dict]):
        token_key = self._token_key(provider_id, client_id)
        tokens = self.load()

        if not token:
            if token_key in tokens:
                del tokens[token_key]
        else:
            tokens[token_key] = token
        self.save(tokens)


class ConfigFileStorage(BaseStorage):

    def __init__(self, path: Optional[str] = None, config_name=None):
        self.path = (
            path
            or os.path.join(
                platformdirs.user_config_dir(config_name or 'PythonCliAuth', ensure_exists=True),
                'tokens.json'
            )
        )

    def load(self):
        log.debug("Load tokens from %s", self.path)
        if not os.path.exists(self.path):
            log.debug("Tokens file %s doest not exists", self.path)
            return {}
        with open(self.path, 'r') as f:
            return json.load(f)

    def save(self, tokens: dict):
        log.debug("Save tokens to %s", self.path)
        try:
            with open(self.path, 'w') as f:
                json.dump(tokens, f)
        except IOError:
            log.exception('Error saving tokens to %s', self.path)


class KeyringStorage(BaseStorage):

    def __init__(self, service_name: Optional[str] = None):
        self.service_name = service_name if service_name else 'python-cli-oauth2'

    def get_token(self, provider_id: str, client_id: str):
        log.debug("Get token for %s@%s from keyring", client_id, provider_id)
        raw_token = keyring.get_password(self.service_name, self._token_key(provider_id, client_id))
        return json.loads(raw_token) if raw_token else None

    def set_token(self, provider_id: str, client_id: str, token: Optional[dict]):
        log.debug("Save token for %s@%s to keyring", client_id, provider_id)
        keyring.set_password(
            self.service_name,
            self._token_key(provider_id, client_id),
            json.dumps(token)
        )


class NoneStorage(BaseStorage):

    def load(self):
        return {}

    def save(self, tokens: dict):
        pass
