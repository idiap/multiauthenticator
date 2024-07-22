# Copyright © Idiap Research Institute <contact@idiap.ch>
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test module for the deprecated features of the MultiAuthenticator class"""
import pytest

from jupyterhub.auth import PAMAuthenticator
from oauthenticator.gitlab import GitLabOAuthenticator
from oauthenticator.google import GoogleOAuthenticator

from ..multiauthenticator import PREFIX_SEPARATOR
from ..multiauthenticator import MultiAuthenticator


def test_service_name():
    gitlab_service_name = "gitlab-service"
    google_service_name = "google-service"
    authenticators = [
        (
            GitLabOAuthenticator,
            "/gitlab",
            {
                "service_name": gitlab_service_name,
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/hub/gitlab/oauth_callback",
            },
        ),
        (
            GoogleOAuthenticator,
            "/google",
            {
                "service_name": google_service_name,
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/hub/othergoogle/oauth_callback",
            },
        ),
    ]
    MultiAuthenticator.authenticators = authenticators

    multi_authenticator = MultiAuthenticator()

    custom_html = multi_authenticator.get_custom_html("http://example.com")

    assert f"Sign in with {gitlab_service_name}" in custom_html
    assert f"Sign in with {google_service_name}" in custom_html


def test_same_authenticators():
    MultiAuthenticator.authenticators = [
        (
            GoogleOAuthenticator,
            "/mygoogle",
            {
                "service_name": "My Google",
                "client_id": "yyyyy",
                "client_secret": "yyyyy",
                "oauth_callback_url": "http://example.com/hub/mygoogle/oauth_callback",
            },
        ),
        (
            GoogleOAuthenticator,
            "/othergoogle",
            {
                "service_name": "Other Google",
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/hub/othergoogle/oauth_callback",
            },
        ),
    ]

    multi_authenticator = MultiAuthenticator()
    assert len(multi_authenticator._authenticators) == 2
    assert multi_authenticator.get_custom_html("").count("\n") == 13

    handlers = multi_authenticator.get_handlers("")
    assert len(handlers) == 6
    for path, handler in handlers:
        assert isinstance(handler.authenticator, GoogleOAuthenticator)
        if "mygoogle" in path:
            assert handler.authenticator.service_name == "My Google"
        elif "othergoogle" in path:
            assert handler.authenticator.service_name == "Other Google"
        else:
            raise ValueError(f"Unknown path: {path}")


def test_username_prefix_validation_with_service_name(invalid_name, caplog):
    MultiAuthenticator.authenticators = [
        (
            PAMAuthenticator,
            "/pam",
            {"service_name": invalid_name, "allowed_users": {"test"}},
        ),
    ]

    with pytest.raises(ValueError) as excinfo:
        MultiAuthenticator()

    assert f"Service name cannot contain {PREFIX_SEPARATOR}" in str(excinfo.value)
    assert len(caplog.records) == 1
    assert (
        caplog.records[0].message
        == "service_name is deprecated, please create a subclass and set the login_service class variable"
    )
