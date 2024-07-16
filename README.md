<!--
Copyright © Idiap Research Institute <contact@idiap.ch>

SPDX-License-Identifier: BSD-3-Clause
-->

# JupyterHub OAuthenticator + LDAPAuthenticator ++... = MultiAuthenticator ❤️

The MultiAuthenticator is multiplexer authenticator class that allows to use
more than one authentication option with JupyterHub.

## Installation

```
$ pip install git+https://github.com/idiap/multiauthenticator
```

## Configuration

The MultiAuthenticator class only has one configuration point: authenticators.

This property shall contain a list of tuple with the following content:

- Authenticator class (i.e. GitLabAuthenticator, LDAPAuthenticator)
- The URL scope (i.e. /gitlab, /ldap)
- A dictionary with the authenticator's configuration

As an example:

```python
from oauthenticator.github import GitHubOAuthenticator
from oauthenticator.google import GoogleOAuthenticator
from oauthenticator.gitlab import GitLabOAuthenticator
from jupyterhub.auth import PAMAuthenticator

c.MultiAuthenticator.authenticators = [
    (GitHubOAuthenticator, '/github', {
        'client_id': 'XXXX',
        'client_secret': 'YYYY',
        'oauth_callback_url': 'https://jupyterhub.example.com/hub/github/oauth_callback'
    }),
    (GoogleOAuthenticator, '/google', {
        'client_id': 'xxxx',
        'client_secret': 'yyyy',
        'oauth_callback_url': 'https://jupyterhub.example.com/hub/google/oauth_callback'
    }),
    (GitLabOAuthenticator, '/gitlab', {
        "client_id": "ZZZZ",
        "client_secret": "AAAAA",
        "oauth_callback_url": "https://jupyterhub.example.com/hub/gitlab/oauth_callback",
        "gitlab_url": "https://gitlab.example.com"
    }),
    (PAMAuthenticator, "/pam", {"service_name": "PAM"}),
]

c.JupyterHub.authenticator_class = 'multiauthenticator.multiauthenticator.MultiAuthenticator'
```
