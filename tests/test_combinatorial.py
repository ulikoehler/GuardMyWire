"""Exhaustive parameterized combinatorial tests for config generation functions.
This module uses heavy cross-product parameterization to achieve broad input coverage."""
import itertools
import pytest

from guardmywire import (
    generate_interface_config,
    generate_peer_config,
    generate_mikrotik_interface_config,
    generate_mikrotik_peer_config,
    generate_openwrt_interface_config,
    generate_openwrt_peer_config,
    is_ipv6,
    is_reachable,
    is_any_reachable,
    should_connect_to,
    get_keepalive,
    key_filenames,
)


# ===================================================================
# Data pools for cross-product testing
# ===================================================================
_NAMES = ["peer1", "MyRouter", "office1.mydomain.org", "test-peer", "peer_42", "R2D2"]
_KEYS = [
    "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NQ==",
    "cFakEPrivateKeyBase64Encoded000000000000000=",
    "shortkey",
]
_SINGLE_ADDRS = [
    "10.0.0.1/24",
    "192.168.1.1/32",
    "172.16.0.1/16",
    "fd00::1/64",
    "10.0.0.1/8",
]
_PORTS = [None, 51820, 22781, 1, 65535, 0]
_ENDPOINTS = [None, "1.2.3.4:51820", "vpn.example.com:22781", "[::1]:51820", "host:1"]
_KEEPALIVES = [0, 10, 25, 30, 60, 120, 300]
_PSKS = [None, "pFakePSK0000000000000000000000000000000000000=", ""]
_ALLOWED_IPS = [
    ["10.0.0.0/24"],
    ["10.0.0.1/32"],
    ["0.0.0.0/0"],
    ["10.0.0.1/32", "fd00::1/128"],
    ["192.168.0.0/16", "10.0.0.0/8"],
    [],
]
_MULTI_ADDRS = [
    ["10.0.0.1/24"],
    ["10.0.0.1/24", "fd00::1/64"],
    ["192.168.1.1/32", "172.16.0.1/16"],
]
_IFACE_NAMES = ["wg0", "WGPointToMultipoint", "wireguard1", None]
_ROUTE_LISTS = [
    [],
    ["192.168.1.0/24"],
    ["10.0.0.0/8", "172.16.0.0/12"],
]


# ===================================================================
# generate_interface_config: 6 names × 3 keys × 5 addrs × 6 ports = 540 tests
# ===================================================================
class TestInterfaceConfigCombinatorial:
    @pytest.mark.parametrize("name", _NAMES)
    @pytest.mark.parametrize("key", _KEYS)
    @pytest.mark.parametrize("addr", _SINGLE_ADDRS)
    @pytest.mark.parametrize("port", _PORTS)
    def test_all_combos(self, name, key, addr, port):
        cfg = generate_interface_config(name, key, addr, port)
        assert "[Interface]" in cfg
        assert f"PrivateKey = {key}" in cfg
        assert f"Address = {addr}" in cfg
        assert f"# Name = {name}" in cfg
        if port is not None:
            assert f"ListenPort = {port}" in cfg
        else:
            assert "ListenPort" not in cfg


# ===================================================================
# generate_peer_config: 6 names × 3 psks × 5 endpoints × 6 allowed_ips = 540 tests
# ===================================================================
class TestPeerConfigCombinatorial:
    @pytest.mark.parametrize("name", _NAMES)
    @pytest.mark.parametrize("psk", _PSKS)
    @pytest.mark.parametrize("endpoint", _ENDPOINTS)
    @pytest.mark.parametrize("allowed_ips", _ALLOWED_IPS)
    def test_all_combos(self, name, psk, endpoint, allowed_ips):
        cfg = generate_peer_config(name, "PUBKEY", psk, allowed_ips=allowed_ips, endpoint=endpoint, keepalive=30)
        assert "[Peer]" in cfg
        assert f"# Name = {name}" in cfg
        assert "PublicKey = PUBKEY" in cfg
        assert f"AllowedIPs = {', '.join(allowed_ips)}" in cfg
        if endpoint is not None:
            assert f"Endpoint = {endpoint}" in cfg
        else:
            assert "Endpoint" not in cfg
        if psk is not None:
            assert f"PresharedKey = {psk}" in cfg
        else:
            assert "PresharedKey" not in cfg


# ===================================================================
# generate_peer_config with varied keepalives: 6 names × 7 keepalives = 42 tests
# ===================================================================
class TestPeerConfigKeepaliveCombinatorial:
    @pytest.mark.parametrize("name", _NAMES)
    @pytest.mark.parametrize("keepalive", _KEEPALIVES)
    def test_keepalive_combos(self, name, keepalive):
        cfg = generate_peer_config(name, "PUB", None, keepalive=keepalive)
        assert f"PersistentKeepalive = {keepalive}" in cfg


# ===================================================================
# generate_mikrotik_peer_config: 3 names × 5 endpoints × 3 psks × 3 route_lists = 135 tests
# ===================================================================
class TestMikrotikPeerCombinatorial:
    @pytest.mark.parametrize("name", _NAMES[:3])
    @pytest.mark.parametrize("endpoint", _ENDPOINTS)
    @pytest.mark.parametrize("psk", _PSKS)
    @pytest.mark.parametrize("routes", _ROUTE_LISTS)
    def test_all_combos(self, name, endpoint, psk, routes):
        cfg = generate_mikrotik_peer_config(
            name, "PUBKEY", psk, ["10.0.0.1/32"], "wg0",
            endpoint=endpoint, keepalive=30,
            provides_routes=routes, addresses=["10.0.0.2/24"]
        )
        assert "/interface wireguard peers add" in cfg
        assert f'comment="{name}"' in cfg
        if endpoint is not None:
            addr, _, port = endpoint.rpartition(":")
            assert f"endpoint-address={addr}" in cfg
        else:
            assert "endpoint-address" not in cfg
        if psk is not None:
            assert f'preshared-key="{psk}"' in cfg
        else:
            assert "preshared-key" not in cfg
        for route in routes:
            assert f'dst-address="{route}"' in cfg


# ===================================================================
# generate_mikrotik_interface_config: 3 addrs × 4 iface × 6 ports = 72 tests
# ===================================================================
class TestMikrotikInterfaceCombinatorial:
    @pytest.mark.parametrize("addresses", _MULTI_ADDRS)
    @pytest.mark.parametrize("iface", _IFACE_NAMES)
    @pytest.mark.parametrize("port", _PORTS)
    def test_all_combos(self, addresses, iface, port):
        cfg = generate_mikrotik_interface_config("testpeer", "PRIVKEY", addresses, iface, port)
        effective_iface = iface if iface is not None else "testpeer"
        assert f"name={effective_iface}" in cfg
        assert "mtu=1420" in cfg
        for addr in addresses:
            assert f"address={addr}" in cfg
        if port is not None:
            assert f"listen-port={port}" in cfg


# ===================================================================
# generate_openwrt_interface_config: 3 addrs × 4 iface × 6 ports = 72 tests
# ===================================================================
class TestOpenwrtInterfaceCombinatorial:
    @pytest.mark.parametrize("addresses", _MULTI_ADDRS)
    @pytest.mark.parametrize("iface", _IFACE_NAMES)
    @pytest.mark.parametrize("port", _PORTS)
    def test_all_combos(self, addresses, iface, port):
        cfg = generate_openwrt_interface_config("testpeer", "PRIVKEY", addresses, iface, port)
        effective_iface = iface if iface is not None else "testpeer"
        assert f"config interface '{effective_iface}'" in cfg
        assert "option proto 'wireguard'" in cfg
        for addr in addresses:
            assert f"list addresses '{addr}'" in cfg
        if port is not None:
            assert f"option listen_port '{port}'" in cfg


# ===================================================================
# generate_openwrt_peer_config: 3 names × 5 endpoints × 6 allowed_ips × 2 keepalives = 180 tests
# ===================================================================
class TestOpenwrtPeerCombinatorial:
    @pytest.mark.parametrize("name", _NAMES[:3])
    @pytest.mark.parametrize("endpoint", _ENDPOINTS)
    @pytest.mark.parametrize("allowed_ips", _ALLOWED_IPS)
    @pytest.mark.parametrize("keepalive", [30, 120])
    def test_all_combos(self, name, endpoint, allowed_ips, keepalive):
        cfg = generate_openwrt_peer_config(
            name, "PUBKEY", "PSK", allowed_ips, "wg0",
            endpoint=endpoint, keepalive=keepalive
        )
        assert "config wireguard_wg0" in cfg
        assert f"option description '{name}'" in cfg
        assert f"option persistent_keepalive '{keepalive}'" in cfg
        for ip in allowed_ips:
            assert f"list allowed_ips '{ip}'" in cfg


# ===================================================================
# is_ipv6: exhaustive address list
# ===================================================================
class TestIsIPv6Exhaustive:
    _IPV6_ADDRS = [
        "::", "::1", "::ffff:192.168.1.1",
        "fe80::1", "fe80::1%eth0",
        "fd00::1", "fd00::abcd:1234",
        "2001:db8::1", "2001:0db8:85a3::8a2e:0370:7334",
        "fd00::1/64", "fd00::1/128",
        "::1/128", "fe80::/10",
        "2001:db8::/32", "fc00::/7",
    ]
    _IPV4_ADDRS = [
        "10.0.0.1", "192.168.1.1", "172.16.0.1",
        "255.255.255.255", "0.0.0.0",
        "10.0.0.1/24", "192.168.0.0/16",
        "1.2.3.4", "127.0.0.1", "8.8.8.8",
        "10.0.0.0/8", "172.16.0.0/12",
        "192.168.100.0/24", "10.82.85.1/24",
    ]
    _NON_ADDRS = [
        "", "not-an-address", "abcdef", "12345",
        "hello world", "foo.bar.baz", "1234:5678",
        "/24", "256.256.256.256",
    ]

    @pytest.mark.parametrize("addr", _IPV6_ADDRS)
    def test_ipv6_detected(self, addr):
        assert is_ipv6(addr) is True

    @pytest.mark.parametrize("addr", _IPV4_ADDRS)
    def test_ipv4_not_detected(self, addr):
        assert is_ipv6(addr) is False

    @pytest.mark.parametrize("addr", _NON_ADDRS)
    def test_non_addr_not_detected(self, addr):
        assert is_ipv6(addr) is False


# ===================================================================
# should_connect_to: exhaustive rule/type matrix with many rule sets
# ===================================================================
class TestShouldConnectToExhaustive:
    _RULE_SETS = [
        # Standard point-to-multipoint
        {
            "rules": {
                "Mobile": {"connect_to": ["Router"]},
                "Desktop": {"connect_to": ["Router"]},
                "Notebook": {"connect_to": ["Router"]},
                "Router": {"connect_to": ["*"]},
            },
            "type_pairs": [
                ("Mobile", "Router", True),
                ("Mobile", "Desktop", False),
                ("Mobile", "Notebook", False),
                ("Mobile", "Mobile", False),
                ("Desktop", "Router", True),
                ("Desktop", "Desktop", False),
                ("Notebook", "Router", True),
                ("Notebook", "Notebook", False),
                ("Router", "Mobile", True),
                ("Router", "Desktop", True),
                ("Router", "Notebook", True),
                ("Router", "Router", True),
            ],
        },
        # Site-to-site
        {
            "rules": {"Server": {"connect_to": ["*"]}},
            "type_pairs": [
                ("Server", "Server", True),
                ("Server", "Client", True),
                ("Server", "Unknown", True),
            ],
        },
        # Multi-target
        {
            "rules": {
                "A": {"connect_to": ["B", "C"]},
                "B": {"connect_to": ["A"]},
                "C": {"connect_to": []},
            },
            "type_pairs": [
                ("A", "B", True),
                ("A", "C", True),
                ("A", "A", False),
                ("B", "A", True),
                ("B", "B", False),
                ("B", "C", False),
                ("C", "A", False),
                ("C", "B", False),
                ("C", "C", False),
            ],
        },
        # Empty connect_to
        {
            "rules": {"X": {"connect_to": []}},
            "type_pairs": [
                ("X", "X", False),
                ("X", "Y", False),
            ],
        },
        # No connect_to key (defaults to wildcard)
        {
            "rules": {"Z": {"keepalive": 30}},
            "type_pairs": [
                ("Z", "Z", True),
                ("Z", "Anything", True),
            ],
        },
    ]

    @pytest.mark.parametrize("rule_set", _RULE_SETS, ids=[
        "p2mp", "s2s", "multi_target", "empty_connect", "no_connect_key"
    ])
    def test_rule_set(self, rule_set):
        rules = rule_set["rules"]
        for our_type, peer_type, expected in rule_set["type_pairs"]:
            result = should_connect_to(rules, our_type, peer_type)
            assert result == expected, f"should_connect_to({our_type}, {peer_type}) = {result}, expected {expected}"

    # Unknown type in various rule sets
    @pytest.mark.parametrize("rules", [
        {"A": {"connect_to": ["*"]}},
        {"B": {"connect_to": ["A"]}},
        {},
    ])
    @pytest.mark.parametrize("unknown", ["Unknown", "Missing", "", "123"])
    def test_unknown_type(self, rules, unknown):
        assert should_connect_to(rules, unknown, "A") is False


# ===================================================================
# get_keepalive: many rules × types
# ===================================================================
class TestGetKeepaliveExhaustive:
    _RULES = {
        "Mobile": {"keepalive": 120},
        "Desktop": {"keepalive": 60},
        "Notebook": {"keepalive": 30},
        "Router": {"keepalive": 25},
        "Server": {"keepalive": 0},
        "NoKeepalive": {},
        "HighKeepalive": {"keepalive": 65535},
    }

    @pytest.mark.parametrize("type_name,expected", [
        ("Mobile", 120),
        ("Desktop", 60),
        ("Notebook", 30),
        ("Router", 25),
        ("Server", 0),
        ("NoKeepalive", 30),
        ("HighKeepalive", 65535),
    ])
    def test_known_types(self, type_name, expected):
        assert get_keepalive(self._RULES, type_name) == expected

    @pytest.mark.parametrize("unknown", [
        "Unknown", "Alien", "", "MOBILE", "mobile", "desktop", "123",
        "Router1", "Server2", "NoSuchType",
    ])
    def test_unknown_defaults_30(self, unknown):
        assert get_keepalive(self._RULES, unknown) == 30


# ===================================================================
# key_filenames exhaustive with special characters
# ===================================================================
class TestKeyFilenamesExhaustive:
    @pytest.mark.parametrize("config_name", [
        "simple", "path/to/config", "my-config", "config_v2",
        "CamelCase", "123", "a.b.c",
    ])
    @pytest.mark.parametrize("peer_name", [
        "peer1", "office1.mydomain.org", "my-peer", "peer_42",
        "UPPERCASE", "MiXeD", "123numeric", "a.b.c",
    ])
    def test_filenames(self, config_name, peer_name):
        priv, pub, psk = key_filenames(config_name, peer_name)
        expected_base = f"{config_name}/keys/{peer_name}"
        assert priv == f"{expected_base}.privkey"
        assert pub == f"{expected_base}.pubkey"
        assert psk == f"{expected_base}.psk"


# ===================================================================
# is_reachable/is_any_reachable cross-product
# ===================================================================
class TestReachabilityExhaustive:
    _REACHABLE_PEERS = [
        {"endpoint": "1.2.3.4:51820"},
        {"endpoint": "vpn.example.com:22781"},
        {"endpoint": "[::1]:51820"},
        {"endpoint": "host:1"},
        {"endpoint": ""},
        {"name": "p", "endpoint": "x:1"},
        {"name": "p", "type": "Router", "endpoint": "x:1"},
    ]
    _UNREACHABLE_PEERS = [
        {},
        {"name": "peer1"},
        {"name": "p", "type": "Mobile"},
        {"addresses": ["10.0.0.1/24"]},
        {"name": "p", "disabled": True},
    ]

    @pytest.mark.parametrize("peer", _REACHABLE_PEERS)
    def test_reachable(self, peer):
        assert is_reachable(peer) is True

    @pytest.mark.parametrize("peer", _UNREACHABLE_PEERS)
    def test_unreachable(self, peer):
        assert is_reachable(peer) is False

    @pytest.mark.parametrize("p1", _REACHABLE_PEERS[:4])
    @pytest.mark.parametrize("p2", _REACHABLE_PEERS[:4])
    def test_both_reachable(self, p1, p2):
        assert is_any_reachable(p1, p2) is True

    @pytest.mark.parametrize("p1", _REACHABLE_PEERS[:4])
    @pytest.mark.parametrize("p2", _UNREACHABLE_PEERS[:4])
    def test_first_reachable_only(self, p1, p2):
        assert is_any_reachable(p1, p2) is True

    @pytest.mark.parametrize("p1", _UNREACHABLE_PEERS[:4])
    @pytest.mark.parametrize("p2", _REACHABLE_PEERS[:4])
    def test_second_reachable_only(self, p1, p2):
        assert is_any_reachable(p1, p2) is True

    @pytest.mark.parametrize("p1", _UNREACHABLE_PEERS[:4])
    @pytest.mark.parametrize("p2", _UNREACHABLE_PEERS[:4])
    def test_neither_reachable(self, p1, p2):
        assert is_any_reachable(p1, p2) is False
