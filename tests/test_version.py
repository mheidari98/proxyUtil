import importlib.metadata

import proxyUtil


def test_version_string():
    assert proxyUtil.__version__ == "0.5.0"


def test_metadata_matches_module():
    # If this fails it usually means the wheel/install is stale; reinstall.
    assert importlib.metadata.version("proxyUtil") == proxyUtil.__version__
