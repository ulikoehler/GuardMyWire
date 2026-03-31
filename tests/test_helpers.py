"""Tests for pure helper functions: is_ipv6, is_reachable, is_any_reachable,
should_connect_to, get_keepalive, key_filenames."""
import itertools
import os
import pytest

from guardmywire import (
    is_ipv6,
    is_reachable,
    is_any_reachable,
    should_connect_to,
    get_keepalive,
    key_filenames,
)


# ===================================================================
# is_ipv6
# ===================================================================
class TestIsIPv6:
    @pytest.mark.parametrize("addr", [
        "::1",
        "fe80::1",
        "fd00::1",
        "2001:db8::1",
        "::ffff:192.168.1.1",
        "::",
        "fe80::1%eth0",
        "::1/128",
        "fd00::abcd:1234",
        "2001:0db8:85a3::8a2e:0370:7334",
    ])
    def test_ipv6_addresses_detected(self, addr):
        assert is_ipv6(addr) is True

    @pytest.mark.parametrize("addr", [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "10.0.0.1/24",
        "192.168.0.0/16",
        "1.2.3.4",
        "127.0.0.1",
        "8.8.8.8",
    ])
    def test_ipv4_addresses_not_detected(self, addr):
        assert is_ipv6(addr) is False

    @pytest.mark.parametrize("addr", [
        "",
        "not-an-address",
        "abcdef",
        "12345",
        "hello world",
    ])
    def test_non_address_strings(self, addr):
        assert is_ipv6(addr) is False


# ===================================================================
# is_reachable
# ===================================================================
class TestIsReachable:
    @pytest.mark.parametrize("peer,expected", [
        ({"endpoint": "1.2.3.4:51820"}, True),
        ({"endpoint": "vpn.example.com:51820"}, True),
        ({"endpoint": "[::1]:51820"}, True),
        ({"endpoint": ""}, True),  # key present, even if empty
        ({}, False),
        ({"name": "peer1"}, False),
        ({"name": "peer1", "addresses": ["10.0.0.1/24"]}, False),
        ({"endpoint": "host:0"}, True),
        ({"endpoint": "host:65535"}, True),
        ({"name": "a", "type": "Mobile"}, False),
    ])
    def test_is_reachable(self, peer, expected):
        assert is_reachable(peer) == expected

    def test_disabled_peer_with_endpoint(self):
        peer = {"endpoint": "1.2.3.4:51820", "disabled": True}
        assert is_reachable(peer) is True  # disabled doesn't affect reachability check


# ===================================================================
# is_any_reachable  (4 combos × multiple endpoint variants)
# ===================================================================
class TestIsAnyReachable:
    REACHABLE = {"endpoint": "1.2.3.4:51820"}
    UNREACHABLE = {"name": "peer"}

    @pytest.mark.parametrize("p1,p2,expected", [
        ({"endpoint": "a:1"}, {"endpoint": "b:2"}, True),
        ({"endpoint": "a:1"}, {}, True),
        ({}, {"endpoint": "b:2"}, True),
        ({}, {}, False),
    ])
    def test_basic_combos(self, p1, p2, expected):
        assert is_any_reachable(p1, p2) == expected

    # Cross-product: mix endpoints
    _ENDPOINTS = [
        {"endpoint": "1.2.3.4:51820"},
        {"endpoint": "vpn.example.com:51820"},
        {"endpoint": "[::1]:51820"},
        {"endpoint": ""},
    ]
    _NO_ENDPOINTS = [
        {},
        {"name": "x"},
        {"addresses": ["10.0.0.1/24"]},
    ]

    @pytest.mark.parametrize("p1", _ENDPOINTS)
    @pytest.mark.parametrize("p2", _ENDPOINTS)
    def test_both_reachable(self, p1, p2):
        assert is_any_reachable(p1, p2) is True

    @pytest.mark.parametrize("p1", _ENDPOINTS)
    @pytest.mark.parametrize("p2", _NO_ENDPOINTS)
    def test_first_reachable(self, p1, p2):
        assert is_any_reachable(p1, p2) is True

    @pytest.mark.parametrize("p1", _NO_ENDPOINTS)
    @pytest.mark.parametrize("p2", _ENDPOINTS)
    def test_second_reachable(self, p1, p2):
        assert is_any_reachable(p1, p2) is True

    @pytest.mark.parametrize("p1", _NO_ENDPOINTS)
    @pytest.mark.parametrize("p2", _NO_ENDPOINTS)
    def test_neither_reachable(self, p1, p2):
        assert is_any_reachable(p1, p2) is False


# ===================================================================
# should_connect_to
# ===================================================================
class TestShouldConnectTo:
    RULES_STANDARD = {
        "Mobile": {"connect_to": ["Router"], "keepalive": 120},
        "Desktop": {"connect_to": ["Router"], "keepalive": 60},
        "Notebook": {"connect_to": ["Router"], "keepalive": 30},
        "Router": {"connect_to": ["*"], "keepalive": 30},
    }

    RULES_SITE2SITE = {
        "Server": {"connect_to": ["*"], "keepalive": 60},
    }

    TYPES = ["Mobile", "Desktop", "Notebook", "Router"]

    # --- Standard rules: exhaustive type×type matrix ---
    @pytest.mark.parametrize("our_type,peer_type,expected", [
        ("Mobile", "Router", True),
        ("Mobile", "Mobile", False),
        ("Mobile", "Desktop", False),
        ("Mobile", "Notebook", False),
        ("Desktop", "Router", True),
        ("Desktop", "Desktop", False),
        ("Desktop", "Mobile", False),
        ("Desktop", "Notebook", False),
        ("Notebook", "Router", True),
        ("Notebook", "Notebook", False),
        ("Notebook", "Mobile", False),
        ("Notebook", "Desktop", False),
        ("Router", "Mobile", True),
        ("Router", "Desktop", True),
        ("Router", "Notebook", True),
        ("Router", "Router", True),
    ])
    def test_standard_rules(self, our_type, peer_type, expected):
        assert should_connect_to(self.RULES_STANDARD, our_type, peer_type) == expected

    # --- Site2Site rules ---
    @pytest.mark.parametrize("peer_type", ["Server", "Client", "Unknown", "Mobile"])
    def test_site2site_wildcard(self, peer_type):
        assert should_connect_to(self.RULES_SITE2SITE, "Server", peer_type) is True

    # --- Unknown type ---
    @pytest.mark.parametrize("our_type", ["Unknown", "Alien", "", "123"])
    def test_unknown_our_type(self, our_type):
        assert should_connect_to(self.RULES_STANDARD, our_type, "Router") is False

    # --- Empty rules ---
    def test_empty_rules(self):
        assert should_connect_to({}, "Mobile", "Router") is False

    # --- Rules with no connect_to key ---
    def test_missing_connect_to_defaults_to_wildcard(self):
        rules = {"Mobile": {"keepalive": 30}}
        assert should_connect_to(rules, "Mobile", "AnythingGoes") is True

    # --- Multiple specific targets ---
    @pytest.mark.parametrize("peer_type,expected", [
        ("Router", True),
        ("Server", True),
        ("Client", False),
        ("Mobile", False),
    ])
    def test_multiple_targets(self, peer_type, expected):
        rules = {"Hybrid": {"connect_to": ["Router", "Server"]}}
        assert should_connect_to(rules, "Hybrid", peer_type) == expected

    # --- Single target ---
    @pytest.mark.parametrize("peer_type,expected", [
        ("OnlyOne", True),
        ("Other", False),
    ])
    def test_single_target(self, peer_type, expected):
        rules = {"A": {"connect_to": ["OnlyOne"]}}
        assert should_connect_to(rules, "A", peer_type) == expected

    # --- Empty connect_to list ---
    def test_empty_connect_to(self):
        rules = {"A": {"connect_to": []}}
        assert should_connect_to(rules, "A", "anything") is False

    # --- Wildcard plus other entries ---
    def test_wildcard_with_extras(self):
        rules = {"A": {"connect_to": ["*", "Router"]}}
        assert should_connect_to(rules, "A", "Any") is True


# ===================================================================
# get_keepalive
# ===================================================================
class TestGetKeepalive:
    RULES = {
        "Mobile": {"keepalive": 120},
        "Desktop": {"keepalive": 60},
        "Notebook": {"keepalive": 30},
        "Router": {"keepalive": 30},
        "Server": {"keepalive": 0},
        "NoKeepalive": {},
    }

    @pytest.mark.parametrize("type_name,expected", [
        ("Mobile", 120),
        ("Desktop", 60),
        ("Notebook", 30),
        ("Router", 30),
        ("Server", 0),
    ])
    def test_known_types(self, type_name, expected):
        assert get_keepalive(self.RULES, type_name) == expected

    def test_missing_keepalive_defaults_to_30(self):
        assert get_keepalive(self.RULES, "NoKeepalive") == 30

    @pytest.mark.parametrize("type_name", ["Unknown", "Alien", "", "123", "MOBILE"])
    def test_unknown_type_defaults_to_30(self, type_name):
        assert get_keepalive(self.RULES, type_name) == 30

    def test_empty_rules(self):
        assert get_keepalive({}, "Mobile") == 30

    def test_various_keepalive_values(self):
        for val in [0, 1, 10, 30, 60, 120, 300, 65535]:
            rules = {"T": {"keepalive": val}}
            assert get_keepalive(rules, "T") == val


# ===================================================================
# key_filenames
# ===================================================================
class TestKeyFilenames:
    @pytest.mark.parametrize("config_name,peer_name", [
        ("myconfig", "peer1"),
        ("Site2Site", "office1.mydomain.org"),
        ("PointToMultipoint", "MyWireguardRouter"),
        ("a", "b"),
        ("config/subdir", "peer"),
        ("test-config", "my-peer"),
        ("config_with_underscore", "peer_underscore"),
    ])
    def test_returns_three_paths(self, config_name, peer_name):
        priv, pub, psk = key_filenames(config_name, peer_name)
        assert priv == os.path.join(config_name, "keys", f"{peer_name}.privkey")
        assert pub == os.path.join(config_name, "keys", f"{peer_name}.pubkey")
        assert psk == os.path.join(config_name, "keys", f"{peer_name}.psk")

    @pytest.mark.parametrize("config_name,peer_name", [
        ("", "peer"),
        ("config", ""),
        ("", ""),
    ])
    def test_empty_strings(self, config_name, peer_name):
        priv, pub, psk = key_filenames(config_name, peer_name)
        assert priv.endswith(".privkey")
        assert pub.endswith(".pubkey")
        assert psk.endswith(".psk")

    def test_path_components(self):
        priv, pub, psk = key_filenames("cfg", "p")
        assert "keys" in priv
        assert "keys" in pub
        assert "keys" in psk

    @pytest.mark.parametrize("peer_name", [
        "peer with spaces",
        "peer.with.dots",
        "peer-with-dashes",
        "peer_with_underscores",
        "UPPERCASE",
        "MiXeD",
        "123numeric",
    ])
    def test_various_peer_names(self, peer_name):
        priv, pub, psk = key_filenames("cfg", peer_name)
        assert peer_name in priv
        assert peer_name in pub
        assert peer_name in psk
