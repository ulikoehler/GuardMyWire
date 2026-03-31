"""Shared fixtures and helpers for GuardMyWire test suite."""
import json
import os
import shutil
import tempfile
import pytest

# ---------------------------------------------------------------------------
# Sample key material (fake, deterministic)
# ---------------------------------------------------------------------------
FAKE_PRIVKEY = "cFakEPrivateKeyBase64Encoded000000000000000="
FAKE_PUBKEY = "xFakEPublicKeyBase64Encoded0000000000000000="
FAKE_PSK = "pFakEPreSharedKeyBase640000000000000000000000="

FAKE_PRIVKEY2 = "cFakEPrivateKeyBase64Encoded222222222222222="
FAKE_PUBKEY2 = "xFakEPublicKeyBase64Encoded2222222222222222="
FAKE_PSK2 = "pFakEPreSharedKeyBase642222222222222222222222="

FAKE_PRIVKEY3 = "cFakEPrivateKeyBase64Encoded333333333333333="
FAKE_PUBKEY3 = "xFakEPublicKeyBase64Encoded3333333333333333="
FAKE_PSK3 = "pFakEPreSharedKeyBase643333333333333333333333="

# ---------------------------------------------------------------------------
# Example configs (matching the repository examples)
# ---------------------------------------------------------------------------
POINT_TO_MULTIPOINT_CONFIG = {
    "rules": {
        "Mobile": {"connect_to": ["Router"], "IPv6": True, "keepalive": 120},
        "Desktop": {"connect_to": ["Router"], "keepalive": 60},
        "Notebook": {"connect_to": ["Router"], "keepalive": 30},
        "Router": {"connect_to": ["*"], "keepalive": 30},
    },
    "peers": [
        {
            "name": "MyWireguardRouter",
            "endpoint": "my-dyndns-addr.domain.tld:22781",
            "provides_routes": ["192.168.1.0/24"],
            "addresses": ["10.178.212.1/24"],
            "type": "Router",
            "interface_name": "WGPointToMultipoint",
        },
        {
            "name": "MyNotebook",
            "addresses": ["10.178.212.2/24"],
            "type": "Notebook",
            "interface_name": "WGPointToMultipoint",
        },
        {
            "name": "MySecondNotebook",
            "addresses": ["10.178.212.3/24"],
            "type": "Notebook",
            "interface_name": "WGPointToMultipoint",
        },
        {
            "name": "MyDesktop",
            "addresses": ["10.178.212.4/24"],
            "type": "Desktop",
            "interface_name": "WGPointToMultipoint",
        },
    ],
}

SITE2SITE_CONFIG = {
    "rules": {
        "Server": {"connect_to": ["*"], "keepalive": 60},
    },
    "peers": [
        {
            "name": "office1.mydomain.org",
            "endpoint": "my.dyndns.org:19628",
            "provides_routes": ["192.168.100.0/24"],
            "addresses": ["10.82.85.1/24"],
            "type": "Server",
            "interface_name": "wg0",
        },
        {
            "name": "office2.mydomain.org",
            "provides_routes": ["192.168.200.0/24"],
            "addresses": ["10.82.85.2/24"],
            "type": "Server",
            "interface_name": "wg0",
        },
    ],
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def tmp_dir():
    """Create and yield a temp directory; clean up after."""
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def p2mp_config_file(tmp_dir):
    """Write the PointToMultipoint config to a temp JSON file and return its path."""
    path = os.path.join(tmp_dir, "PointToMultipoint.json")
    with open(path, "w") as f:
        json.dump(POINT_TO_MULTIPOINT_CONFIG, f, indent=4)
    return path


@pytest.fixture
def s2s_config_file(tmp_dir):
    """Write the Site2Site config to a temp JSON file and return its path."""
    path = os.path.join(tmp_dir, "Site2Site.json")
    with open(path, "w") as f:
        json.dump(SITE2SITE_CONFIG, f, indent=4)
    return path


def write_config(tmp_dir, config, name="test.json"):
    """Helper – write *config* dict to *name* in *tmp_dir* and return full path."""
    path = os.path.join(tmp_dir, name)
    with open(path, "w") as f:
        json.dump(config, f, indent=4)
    return path


def create_fake_keys(config_name, peer_name, privkey=FAKE_PRIVKEY, pubkey=FAKE_PUBKEY, psk=FAKE_PSK):
    """Create fake key files on disk so load_keys works without wg."""
    keys_dir = os.path.join(config_name, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    for fname, content in [
        (f"{peer_name}.privkey", privkey),
        (f"{peer_name}.pubkey", pubkey),
        (f"{peer_name}.psk", psk),
    ]:
        with open(os.path.join(keys_dir, fname), "w") as f:
            f.write(content)
