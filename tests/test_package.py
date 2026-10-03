"""Verify that the installed package can be imported from the src layout."""

from importlib.metadata import version

import threatpulse


def test_installed_package() -> None:
    assert threatpulse.__name__ == "threatpulse"
    assert version("threatpulse") == "0.1.0"
