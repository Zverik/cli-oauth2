# CLI OAuth2

This Python library help command-line tool authors to use
OAuth2 services. Built using [requests-oauthlib](https://requests-oauthlib.readthedocs.io/)
with parts of [google\_auth\_oauthlib](https://github.com/googleapis/google-auth-library-python-oauthlib).

## Installation

    pip install cli-oauth2

## Usage

Do something like this:

```python
from oauthcli import OpenStreetMapAuth

auth = OpenStreetMapAuth(
    client_id, secret_id, ['read_prefs']
).auth_server(token_test=lambda r: r.get('user/details'))

data = auth.get('user/details.json')
if data.status_code != 200:
    print(f'Error {data.status_code}: {data.text})')
else:
    print(f'Hello, {data.json()["user"]["display_name"]}')
```

Tokens are saved to disk, so subsequent runs won't require authorization.

Auth objects have these methods and properties:

* `auth_server()` opens a web browser and catches the response by
  starting a local server.
* `auth_code()` opens a web browser and expected a user to copy the code
  presented by the provider. It uses `urn:ietf:wg:oauth:2.0:oob` redirect uri.
* `authorized` returns whether there is an active access token.
* `get`, `post` etc call the relevant `requests` methods, but often shadow
  the server name. See the example above.
* `session` is the underlying [OAuth2Session](https://requests-oauthlib.readthedocs.io/en/latest/api.html#oauth-2-0-session) object.

There are some predefined providers:

* `OpenStreetMapAuth`
* `OpenStreetMapDevAuth`
* `GoogleAuth`
* `GitHubAuth`
* `MastodonAuth` (requires a `server` parameter)
* `RedditAuth`
* `FacebookAuth`
* `LinkedInAuth`

Note that only OSM and GitHub providers were tested. I welcome
pull requests with fixes.

If you need to use another provider, just subclass `AuthFlow` and
pass it `provider_id` (the key for the stored token map),
`OAuth2Session(client_id, scope=scopes)`,
`auth_url`, `token_url`, and `client_secret`.

## Cleanup

The tool stores tokens in a json in the configuration directory.
To clean some or all tokens, use the `oauthclean` command-line tool.

## Author and License

Written by Ilya Zverev, published under Apache License 2.0.

Contains portions of [google\_auth\_oauthlib](https://github.com/googleapis/google-auth-library-python-oauthlib)
as of commit 1a9dca889357b93bdad17d75a28ac81e3ba6067f, published under
Apache License 2.0.
