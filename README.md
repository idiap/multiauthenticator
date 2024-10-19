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
$ pip install jupyter-multiauthenticator
```

## Configuration

The MultiAuthenticator class only has one configuration point: authenticators.

This property shall contain a list of tuple with the following content:

- Authenticator class (i.e. GitLabAuthenticator, LDAPAuthenticator)
- The URL scope (i.e. /gitlab, /ldap)
- A dictionary with the authenticator's configuration

As an example:

```python
from jupyterhub.auth import PAMAuthenticator

class MyPamAutenticator(PAMAuthenticator):
    login_service = "PAM"

c.MultiAuthenticator.authenticators = [
    {
        "authenticator_class": 'github',
        "url_prefix": '/github',
        "config": {
            'client_id': 'XXXX',
            'client_secret': 'YYYY',
            'oauth_callback_url': 'https://jupyterhub.example.com/hub/github/oauth_callback'
        }
    },
    {
        "authenticator_class": 'google',
        "url_prefix": '/google',
        "config": {
            'client_id': 'xxxx',
            'client_secret': 'yyyy',
            'oauth_callback_url': 'https://jupyterhub.example.com/hub/google/oauth_callback'
        }
    },
    {
        "authenticator_class": 'gitlab',
        "url_prefix": '/gitlab',
        "config": {
            'client_id': 'ZZZZ',
            'client_secret': 'AAAA',
            'oauth_callback_url': 'https://jupyterhub.example.com/hub/gitlab/oauth_callback'
            "gitlab_url": "https://gitlab.example.com"
        }
    },
    {
        "authenticator_class": MyPamAuthenticator,
        "url_prefix": "/pam",
    },
]

c.JupyterHub.authenticator_class = 'multiauthenticator'
```
