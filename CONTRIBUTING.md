<!--
Copyright © Idiap Research Institute <contact@idiap.ch>

SPDX-License-Identifier: BSD-3-Clause
-->

# Contributing

Welcome! As a [Jupyter](https://jupyter.org) targeted project, we follow the [Jupyter contributor guide](https://jupyter.readthedocs.io/en/latest/contributor/content-contributor.html)
and [Code of Conduct](https://github.com/jupyter/governance/blob/master/conduct/code_of_conduct.md).

To set up a development environment for this repository:

1. Clone this repository:

   ```
   git clone https://github.com/idiap/multiauthenticator
   ```

1. Do a development install with pip

   ```bash
   pip install --editable ".[dev]"
   ```

1. Set up pre-commit hooks for automatic code formatting, etc.

   ```bash
   pip install pre-commit

   pre-commit install --install-hooks
   ```

   You can also invoke the pre-commit hook manually at any time with

   ```bash
   pre-commit run
   ```

1. Run tests

   ```
   pytest
   ```

Feel free to ask for help
