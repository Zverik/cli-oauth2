from .flow import AuthFlow
from requests_oauthlib import OAuth2Session
from typing import Optional, Sequence


class OpenStreetMapAuth(AuthFlow):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scopes: Sequence[str],
        provider_id: str = 'openstreetmap',
        url: str = 'https://www.openstreetmap.org',
    ):
        super().__init__(
            provider_id,
            OAuth2Session(client_id, scope=scopes),
            f'{url.rstrip("/")}/oauth2/authorize',
            f'{url.rstrip("/")}/oauth2/token',
            client_secret,
        )
        self.default_local_host = '127.0.0.1'
        self.url = url.rstrip("/")

    def process_url(self, api: str) -> str:
        return f'{self.url}/api/0.6/{api.lstrip("/")}'


class OpenStreetMapDevAuth(OpenStreetMapAuth):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scopes: Sequence[str],
    ):
        super().__init__(
            client_id, client_secret, scopes,
            'openstreetmap_dev',
            'https://api06.dev.openstreetmap.org'
        )


class GoogleAuth(AuthFlow):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scopes: Sequence[str],
    ):
        super().__init__(
            'google',
            OAuth2Session(client_id, scope=scopes),
            'https://accounts.google.com/o/oauth2/auth',
            'https://oauth2.googleapis.com/token',
            client_secret,
        )


class GitHubAuth(AuthFlow):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scopes: Optional[Sequence[str]] = None,
    ):
        super().__init__(
            'github',
            OAuth2Session(client_id, scope=scopes),
            'https://github.com/login/oauth/authorize',
            'https://github.com/login/oauth/access_token',
            client_secret,
        )

    def process_url(self, api: str) -> str:
        return f'https://api.github.com/{api.lstrip("/")}'


class MastodonAuth(AuthFlow):
    def __init__(
        self,
        server: str,
        client_id: str,
        client_secret: str,
        scopes: Optional[Sequence[str]] = None,
    ):
        super().__init__(
            'mastodon',
            OAuth2Session(client_id, scope=scopes),
            f'{server.rstrip("/")}/oauth2/authorize',
            f'{server.rstrip("/")}/oauth2/token',
            client_secret,
        )
        self.server = server.rstrip('/')

    def process_url(self, api: str) -> str:
        return f'{self.server}/api/v1/{api.lstrip("/")}'


class RedditAuth(AuthFlow):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scopes: Sequence[str],
    ):
        super().__init__(
            'reddit',
            OAuth2Session(client_id, scope=scopes),
            'https://www.reddit.com/oauth2/authorize',
            'https://www.reddit.com/oauth2/access_token',
            client_secret,
        )

    def process_url(self, api: str) -> str:
        return f'https://www.reddit.com/{api.lstrip("/")}'


class FacebookAuth(AuthFlow):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scopes: Sequence[str],
    ):
        super().__init__(
            'facebook',
            OAuth2Session(client_id, scope=scopes),
            'https://www.facebook.com/dialog/oauth',
            'https://graph.facebook.com/oauth/access_token',
            client_secret,
        )


class LinkedInAuth(AuthFlow):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scopes: Sequence[str],
    ):
        super().__init__(
            'linkedin',
            OAuth2Session(client_id, scope=scopes),
            'https://www.linkedin.com/uas/oauth2/authorization',
            'https://www.linkedin.com/uas/oauth2/accessToken',
            client_secret,
        )
