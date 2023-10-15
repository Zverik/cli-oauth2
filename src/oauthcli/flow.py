try:
    from secrets import SystemRandom
except ImportError:  # pragma: NO COVER
    from random import SystemRandom
import contextlib
import socket
import hashlib
import logging
import platformdirs
import json
import webbrowser
import string
import wsgiref.simple_server
import wsgiref.util
import os.path
import sys
from base64 import urlsafe_b64encode
from requests_oauthlib import OAuth2Session
from typing import Optional, Union, Callable


class AuthFlow:
    def __init__(
        self,
        provider_id: str,
        session: OAuth2Session,
        auth_url: str,
        token_url: str,
        client_secret: Optional[str] = None,
    ):
        self.provider_id = provider_id
        self.session = session
        self.session.token_updater = self._save_token
        self.code_verifier = None
        self.auth_url = auth_url
        self.token_url = token_url
        self.client_secret = client_secret
        self.default_local_host = 'localhost'
        self._load_token()

    @property
    def authorized(self) -> bool:
        return self.session.authorized

    def logout(self):
        """Removes a stored token, but does not clear the current session.
        Warning: a request with the current session can refresh and save
        the token, making this call ineffective."""
        self._save_token(None)

    def process_url(self, api: str) -> str:
        return api

    def request(self, method: str, api: str, **kwargs):
        return self.session.request(method, self.process_url(api), **kwargs)

    def get(self, api: str, **kwargs):
        return self.session.get(self.process_url(api), **kwargs)

    def post(self, api: str, **kwargs):
        return self.session.post(self.process_url(api), **kwargs)

    def put(self, api: str, **kwargs):
        return self.session.put(self.process_url(api), **kwargs)

    def patch(self, api: str, **kwargs):
        return self.session.patch(self.process_url(api), **kwargs)

    def delete(self, api: str, **kwargs):
        return self.session.delete(self.process_url(api), **kwargs)

    def head(self, api: str, **kwargs):
        return self.session.head(self.process_url(api), **kwargs)

    def options(self, api: str, **kwargs):
        return self.session.options(self.process_url(api), **kwargs)

    def _load_token(self):
        if not self.session.client_id:
            return
        token_key = f'{self.provider_id}/{self.session.client_id}'
        config_dir = platformdirs.user_config_dir('PythonCliAuth', ensure_exists=True)
        filename = os.path.join(config_dir, 'tokens.json')
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                tokens = json.load(f)
                if token_key in tokens:
                    self.session.token = tokens[token_key]

    def _save_token(self, token: Optional[dict]):
        token_key = f'{self.provider_id}/{self.session.client_id}'
        config_dir = platformdirs.user_config_dir('PythonCliAuth', ensure_exists=True)
        filename = os.path.join(config_dir, 'tokens.json')
        tokens = {}
        try:
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    tokens = json.load(f)
        except IOError:
            pass

        if not token:
            if token_key in tokens:
                del tokens[token_key]
        else:
            tokens[token_key] = token

        try:
            with open(filename, 'w') as f:
                json.dump(tokens, f)
        except IOError:
            logging.exception('Could not save tokens to %s', filename)

    def authorization_url(self, **kwargs):
        # ↓ this is google-specific
        # kwargs.setdefault("access_type", "offline")
        chars = string.ascii_letters + string.digits + "-._~"
        rnd = SystemRandom()
        random_verifier = [rnd.choice(chars) for _ in range(0, 128)]
        self.code_verifier = "".join(random_verifier)

        if self.code_verifier:
            code_hash = hashlib.sha256()
            code_hash.update(str.encode(self.code_verifier))
            unencoded_challenge = code_hash.digest()
            b64_challenge = urlsafe_b64encode(unencoded_challenge)
            code_challenge = b64_challenge.decode().split("=")[0]
            kwargs.setdefault("code_challenge", code_challenge)
            kwargs.setdefault("code_challenge_method", "S256")

        url, state = self.session.authorization_url(self.auth_url, **kwargs)
        return url, state

    def fetch_token(self, **kwargs):
        kwargs.setdefault("client_secret", self.client_secret)
        kwargs.setdefault("code_verifier", self.code_verifier)
        token = self.session.fetch_token(self.token_url, **kwargs)
        self._save_token(token)
        return token

    _DEFAULT_AUTH_CODE_MESSAGE = "Enter the authorization code: "

    _DEFAULT_AUTH_PROMPT_MESSAGE = (
        "Please visit this URL to authorize this application: {url}"
    )

    _DEFAULT_WEB_SUCCESS_MESSAGE = (
        "The authentication flow has completed. You may close this window."
    )

    def _check_auth(self, force: bool, token_test: Optional[Callable] = None) -> bool:
        if not self.authorized or force:
            return False
        ok = True
        if token_test is not None:
            try:
                resp = token_test(self)
                if resp.status_code % 100 == 4:
                    ok = False
            except:  # noqa: E722
                ok = False
        return ok

    def auth_code(
        self,
        authorization_prompt_message=_DEFAULT_AUTH_PROMPT_MESSAGE,
        open_browser=True,
        code_message=_DEFAULT_AUTH_CODE_MESSAGE,
        token_audience=None,
        force: bool = False,
        token_test: Optional[Callable] = None,
        **kwargs
    ):
        """Runs auth flow without starting a web server.
        Note that you must have 'urn:ietf:wg:oauth:2.0:oob' for
        the redirect URL in the provider app settings."""
        if self._check_auth(force, token_test):
            return self

        self.session.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
        auth_url, _ = self.authorization_url(**kwargs)

        if open_browser:
            webbrowser.open(auth_url, new=2, autoraise=True)

        if authorization_prompt_message:
            print(authorization_prompt_message.format(url=auth_url), file=sys.stderr)

        while True:
            auth_code = input(code_message).strip()
            if auth_code:
                break
        self.fetch_token(code=auth_code, audience=token_audience)
        return self

    def _find_open_port(self, ports: list[int]):
        start = 8080 if not ports else ports[0]
        stop = start + 100 if len(ports) < 2 else ports[1]
        for port in range(start, stop):
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                try:
                    sock.bind(('127.0.0.1', port))
                    sock.listen(1)
                except socket.error:
                    is_open = False
                else:
                    is_open = True
            if is_open:
                return port
        raise ConnectionError('Could not find an open port')

    # Copied from google-auth.
    def auth_server(
        self,
        host: Optional[str] = None,
        bind_addr: Optional[int] = None,
        port: Union[int, list[int]] = 8080,
        authorization_prompt_message: Optional[str] = _DEFAULT_AUTH_PROMPT_MESSAGE,
        success_message: str = _DEFAULT_WEB_SUCCESS_MESSAGE,
        open_browser: bool = True,
        redirect_uri_trailing_slash: bool = True,
        timeout_seconds: Optional[int] = None,
        token_audience: Optional[str] = None,
        force: bool = False,
        token_test: Optional[Callable] = None,
        **kwargs
    ):
        """Run the flow using the server strategy.

        The server strategy instructs the user to open the authorization URL in
        their browser and will attempt to automatically open the URL for them.
        It will start a local web server to listen for the authorization
        response. Once authorization is complete the authorization server will
        redirect the user's browser to the local web server. The web server
        will get the authorization code from the response and shutdown. The
        code is then exchanged for a token.

        Args:
            host (str): The hostname for the local redirect server. This will
                be served over http, not https.
            bind_addr (str): Optionally provide an ip address for the redirect
                server to listen on when it is not the same as host
                (e.g. in a container). Default value is None,
                which means that the redirect server will listen
                on the ip address specified in the host parameter.
            port (int / list[int]): The port for the local redirect server.
                When a list, it would find the first open port in the range.
            authorization_prompt_message (str | None): The message to display to tell
                the user to navigate to the authorization URL. If None or empty,
                don't display anything.
            success_message (str): The message to display in the web browser
                the authorization flow is complete.
            open_browser (bool): Whether or not to open the authorization URL
                in the user's browser.
            redirect_uri_trailing_slash (bool): whether or not to add trailing
                slash when constructing the redirect_uri. Default value is True.
            timeout_seconds (int): It will raise an error after the timeout timing
                if there are no credentials response. The value is in seconds.
                When set to None there is no timeout.
                Default value is None.
            token_audience (str): Passed along with the request for an access
                token. Determines the endpoints with which the token can be
                used. Optional.
            force (bool): Set to True to authorize even when already have a token.
            token_test (Callable): Function that receives this object for a param,
                makes a call, and returns the response.
            kwargs: Additional keyword arguments passed through to
                :meth:`authorization_url`.

        Returns:
            google.oauth2.credentials.Credentials: The OAuth 2.0 credentials
                for the user.
        """
        if self._check_auth(force, token_test):
            return self

        if isinstance(port, list):
            port = self._find_open_port(port)

        if not host:
            host = self.default_local_host

        wsgi_app = _RedirectWSGIApp(success_message)
        # Fail fast if the address is occupied
        wsgiref.simple_server.WSGIServer.allow_reuse_address = False
        local_server = wsgiref.simple_server.make_server(
            bind_addr or host, port, wsgi_app, handler_class=_WSGIRequestHandler
        )

        redirect_uri_format = (
            "http://{}:{}/" if redirect_uri_trailing_slash else "http://{}:{}"
        )
        self.session.redirect_uri = redirect_uri_format.format(host, local_server.server_port)
        auth_url, _ = self.authorization_url(**kwargs)

        if open_browser:
            webbrowser.open(auth_url, new=2, autoraise=True)

        if authorization_prompt_message:
            print(authorization_prompt_message.format(url=auth_url), file=sys.stderr)

        local_server.timeout = timeout_seconds
        local_server.handle_request()

        # Note: using https here because oauthlib is very picky that
        # OAuth 2.0 should only occur over https.
        authorization_response = wsgi_app.last_request_uri.replace("http", "https")
        self.fetch_token(
            authorization_response=authorization_response, audience=token_audience
        )

        # This closes the socket
        local_server.server_close()
        return self


class _WSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
    """Custom WSGIRequestHandler.

    Uses a named logger instead of printing to stderr.
    """

    def log_message(self, format, *args):
        # pylint: disable=redefined-builtin
        # (format is the argument name defined in the superclass.)
        logging.info(format, *args)


class _RedirectWSGIApp(object):
    """WSGI app to handle the authorization redirect.

    Stores the request URI and displays the given success message.
    """

    def __init__(self, success_message):
        """
        Args:
            success_message (str): The message to display in the web browser
                the authorization flow is complete.
        """
        self.last_request_uri = None
        self._success_message = success_message

    def __call__(self, environ, start_response):
        """WSGI Callable.

        Args:
            environ (Mapping[str, Any]): The WSGI environment.
            start_response (Callable[str, list]): The WSGI start_response
                callable.

        Returns:
            Iterable[bytes]: The response body.
        """
        start_response("200 OK", [("Content-type", "text/plain; charset=utf-8")])
        self.last_request_uri = wsgiref.util.request_uri(environ)
        return [self._success_message.encode("utf-8")]
