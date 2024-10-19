# Copyright © Idiap Research Institute <contact@idiap.ch>
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test module for the MultiAuthenticator class"""
import jupyterhub
import pytest

from jinja2 import Template
from jupyterhub.auth import DummyAuthenticator
from jupyterhub.auth import PAMAuthenticator
from oauthenticator import OAuthenticator
from oauthenticator.github import GitHubOAuthenticator
from oauthenticator.gitlab import GitLabOAuthenticator
from packaging.version import Version

from ..multiauthenticator import PREFIX_SEPARATOR
from ..multiauthenticator import MultiAuthenticator


class CustomDummyAuthenticator(DummyAuthenticator):
    login_service = "Dummy"

    def normalize_username(self, username):
        return username.upper()


class CustomPAMAuthenticator(PAMAuthenticator):
    login_service = "PAM"


def test_different_authenticators():
    MultiAuthenticator.authenticators = [
        {
            "authenticator_class": "gitlab",
            "url_prefix": "/gitlab",
            "config": {
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/hub/gitlab/oauth_callback",
            },
        },
        {
            "authenticator_class": "oauthenticator.github.GitHubOAuthenticator",
            "url_prefix": "/github",
            "config": {
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/hub/github/oauth_callback",
            },
        },
        {"authenticator_class": CustomPAMAuthenticator, "url_prefix": "/pam"},
    ]

    multi_authenticator = MultiAuthenticator()
    assert len(multi_authenticator._authenticators) == 3
    assert multi_authenticator.get_custom_html("").count("\n") == 20

    routes = multi_authenticator.get_handlers("")
    assert len(routes) == 7

    authenticators = {handler.authenticator for _, handler in routes}

    assert len(authenticators) == 3

    for authenticator in authenticators:
        if isinstance(authenticator, GitLabOAuthenticator):
            assert (
                authenticator.login_url("http://example.com")
                == "http://example.com/gitlab/oauth_login"
            )
            assert (
                authenticator.logout_url("http//example.com")
                == "http//example.com/gitlab/logout"
            )
        elif isinstance(authenticator, GitHubOAuthenticator):
            assert (
                authenticator.login_url("http://example.com")
                == "http://example.com/github/oauth_login"
            )
            assert (
                authenticator.logout_url("http://example.com")
                == "http://example.com/github/logout"
            )
        elif isinstance(authenticator, PAMAuthenticator):
            assert (
                authenticator.login_url("http://example.com")
                == "http://example.com/pam/login"
            )
            assert (
                authenticator.logout_url("http://example.com")
                == "http://example.com/pam/logout"
            )
        else:
            raise ValueError(f"Unknown authenticator: {authenticator}")


def test_extra_configuration():
    allowed_users = {"test_user1", "test_user2"}

    authenticators = [
        {
            "authenticator_class": GitLabOAuthenticator,
            "url_prefix": "/gitlab",
            "config": {
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/hub/gitlab/oauth_callback",
                "allowed_users": allowed_users,
            },
        },
        {
            "authenticator_class": CustomDummyAuthenticator,
            "url_prefix": "/pam",
            "config": {
                "allowed_users": allowed_users,
            },
        },
    ]
    MultiAuthenticator.authenticators = authenticators

    multi_authenticator = MultiAuthenticator()

    for authenticator in multi_authenticator._authenticators:
        assert authenticator.allowed_users == allowed_users


def test_username_prefix():
    MultiAuthenticator.authenticators = [
        {
            "authenticator_class": GitLabOAuthenticator,
            "url_prefix": "/gitlab",
            "config": {
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/hub/gitlab/oauth_callback",
            },
        },
        {"authenticator_class": CustomPAMAuthenticator, "url_prefix": "/pam"},
        {"authenticator_class": CustomDummyAuthenticator, "url_prefix": "/dummy"},
    ]

    multi_authenticator = MultiAuthenticator()
    assert len(multi_authenticator._authenticators) == 3
    assert (
        multi_authenticator._authenticators[0].username_prefix
        == f"gitlab{PREFIX_SEPARATOR}"
    )
    assert (
        multi_authenticator._authenticators[1].username_prefix
        == f"pam{PREFIX_SEPARATOR}"
    )
    assert (
        multi_authenticator._authenticators[2].username_prefix
        == f"DUMMY{PREFIX_SEPARATOR}"
    )


@pytest.mark.asyncio
async def test_authenticated_username_prefix():
    MultiAuthenticator.authenticators = [
        {"authenticator_class": CustomDummyAuthenticator, "url_prefix": "/dummy"},
    ]

    multi_authenticator = MultiAuthenticator()
    assert len(multi_authenticator._authenticators) == 1
    user = await multi_authenticator._authenticators[0].get_authenticated_user(
        None, {"username": "test"}
    )
    assert user["name"] == f"DUMMY{PREFIX_SEPARATOR}TEST"


def test_username_prefix_checks():
    class CustomPAMAuthenticator2(PAMAuthenticator):
        login_service = "PAM2"

    class CustomDummyAuthenticator2(CustomDummyAuthenticator):
        login_service = "Dummy2"

    MultiAuthenticator.authenticators = [
        {
            "authenticator_class": CustomPAMAuthenticator,
            "url_prefix": "/pam",
            "config": {"allowed_users": {"test"}},
        },
        {
            "authenticator_class": CustomPAMAuthenticator2,
            "url_prefix": "/pam2",
            "config": {"blocked_users": {"test2"}},
        },
        {
            "authenticator_class": CustomDummyAuthenticator,
            "url_prefix": "/dummy",
            "config": {"allowed_users": {"TEST3"}},
        },
        {
            "authenticator_class": CustomDummyAuthenticator2,
            "url_prefix": "/dummy2",
            "config": {
                "allowed_users": {"TEST3"},
                "blocked_users": {"TEST4"},
            },
        },
    ]

    multi_authenticator = MultiAuthenticator()
    assert len(multi_authenticator._authenticators) == 4
    authenticator = multi_authenticator._authenticators[0]

    assert authenticator.check_allowed("test") == False
    assert authenticator.check_allowed("pam:test") == True
    assert (
        authenticator.check_blocked_users("test") == False
    )  # Even if no block list, it does not have the correct prefix
    assert authenticator.check_blocked_users("pam:test") == True

    authenticator = multi_authenticator._authenticators[1]
    assert authenticator.check_allowed("test2") == False
    if Version(jupyterhub.__version__) < Version("5"):
        assert (
            authenticator.check_allowed("pam2:test2") == True
        )  # Because allowed_users is empty
    else:
        assert authenticator.check_allowed("pam2:test2") == False
    assert (
        authenticator.check_blocked_users("test2") == False
    )  # Because of missing prefix
    assert (
        authenticator.check_blocked_users("pam2:test2") == False
    )  # Because user is in blocked list

    authenticator = multi_authenticator._authenticators[2]
    assert authenticator.check_allowed("TEST3") == False
    assert authenticator.check_allowed("DUMMY:TEST3") == True
    assert (
        authenticator.check_blocked_users("TEST3") == False
    )  # Because of missing prefix
    assert (
        authenticator.check_blocked_users("DUMMY:TEST3") == True
    )  # Because blocked_users is empty thus allowed

    authenticator = multi_authenticator._authenticators[3]
    assert authenticator.check_allowed("TEST3") == False
    assert authenticator.check_allowed("DUMMY2:TEST3") == True
    assert (
        authenticator.check_blocked_users("TEST3") == False
    )  # Because of missing prefix
    assert (
        authenticator.check_blocked_users("DUMMY2:TEST3") == True
    )  # Because user is not in blocked list
    assert (
        authenticator.check_blocked_users("DUMMY2:TEST4") == False
    )  # Because user is in blocked list


def test_username_prefix_validation_with_login_service(invalid_name):
    class MyAuthenticator(OAuthenticator):
        login_service = invalid_name

    MultiAuthenticator.authenticators = [
        {
            "authenticator_class": MyAuthenticator,
            "url_prefix": "/myauth",
            "config": {
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/myauth/oauth_callback",
            },
        },
    ]

    with pytest.raises(ValueError) as excinfo:
        MultiAuthenticator()

    assert f"Login service cannot contain {PREFIX_SEPARATOR}" in str(excinfo.value)


def test_next_handling():
    MultiAuthenticator.authenticators = [
        {
            "authenticator_class": CustomDummyAuthenticator,
            "url_prefix": "/dummy",
            "config": {"allowed_users": {"test"}},
        },
    ]

    multi_authenticator = MultiAuthenticator()
    html = multi_authenticator.get_custom_html("")

    template = Template(html)

    with_next = template.render({"next": "/next-destination"})
    assert "href='dummy/login?next=/next-destination'" in with_next

    without_next = template.render()
    assert "href='dummy/login'" in without_next

    with_empty_next = template.render({"next": ""})
    assert "href='dummy/login'" in with_empty_next


@pytest.mark.parametrize(
    "prefix,expected", [(None, "DUMMY:TEST"), ("", "TEST"), ("prefix", "PREFIXTEST")]
)
@pytest.mark.asyncio
async def test_prefix(prefix, expected):
    MultiAuthenticator.username_prefix = prefix
    MultiAuthenticator.authenticators = [
        {
            "authenticator_class": CustomDummyAuthenticator,
            "url_prefix": "/dummy",
        },
    ]

    multi_authenticator = MultiAuthenticator()
    assert len(multi_authenticator._authenticators) == 1
    user = await multi_authenticator._authenticators[0].get_authenticated_user(
        None, {"username": "test"}
    )
    assert user["name"] == expected
