# Copyright © Idiap Research Institute <contact@idiap.ch>
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test Configuration"""
import pytest

from ..multiauthenticator import PREFIX_SEPARATOR


@pytest.fixture(params=[f"test me{PREFIX_SEPARATOR}", f"second{PREFIX_SEPARATOR} test"])
def invalid_name(request):
    yield request.param
