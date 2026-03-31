"""Additional parameterized tests for exhaustive coverage of config generation
with varied configurations, types, and topologies. These tests focus on
WireguardConfigurator.generate_configs with different peer/rule combinations."""
import json
import os
import itertools
import pytest

from guardmywire import (
    WireguardConfigurator,
    generate_interface_config,
    generate_peer_config,
    generate_mikrotik_interface_config,
    generate_mikrotik_peer_config,
    generate_openwrt_interface_config,
    generate_openwrt_peer_config,
    should_connect_to,
    is_any_reachable,
    is_reachable,
    get_keepalive,
    is_ipv6,
    _collect_network_counters,
    _next_host_in_network,
    _next_subnet_for_routes,
    _select_most_common_network,
    add_device,
    rename_device,
    format_json,
    list_clients,
)
from tests.conftest import (
    write_config,
    create_fake_keys,
    FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK,
    FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2,
    FAKE_PRIVKEY3, FAKE_PUBKEY3, FAKE_PSK3,
)
import ipaddress
from collections import Counter


# ===================================================================
# Parametric topology tests: 2-type rule sets
# ===================================================================
_TWO_TYPE_RULES = [
    (["A"], ["B"]),    # A->B only
    (["A"], ["*"]),    # A->*, B->A
    (["*"], ["*"]),    # both wildcard
    (["B"], ["A"]),    # reverse
    ([], []),          # nothing connects
    (["*"], []),       # A->*, B->nothing
]

class TestTwoTypeRuleSets:
    @pytest.mark.parametrize("a_targets,b_targets", _TWO_TYPE_RULES)
    def test_connection_matrix(self, a_targets, b_targets):
        rules = {
            "A": {"connect_to": a_targets, "keepalive": 30},
            "B": {"connect_to": b_targets, "keepalive": 60},
        }
        # A->B?
        a_to_b = should_connect_to(rules, "A", "B")
        expected_a_to_b = "*" in a_targets or "B" in a_targets
        assert a_to_b == expected_a_to_b

        # B->A?
        b_to_a = should_connect_to(rules, "B", "A")
        expected_b_to_a = "*" in b_targets or "A" in b_targets
        assert b_to_a == expected_b_to_a

    @pytest.mark.parametrize("a_targets,b_targets", _TWO_TYPE_RULES)
    def test_topology_generation(self, tmp_dir, a_targets, b_targets):
        rules = {
            "A": {"connect_to": a_targets, "keepalive": 30},
            "B": {"connect_to": b_targets, "keepalive": 60},
        }
        config = {
            "rules": rules,
            "peers": [
                {"name": "peer_a", "type": "A", "addresses": ["10.0.0.1/24"], "endpoint": "a:1"},
                {"name": "peer_b", "type": "B", "addresses": ["10.0.0.2/24"], "endpoint": "b:2"},
            ],
        }
        path = write_config(tmp_dir, config)
        wg = WireguardConfigurator(path)
        os.makedirs(wg.keys_dir, exist_ok=True)
        create_fake_keys(wg.config_name, "peer_a")
        create_fake_keys(wg.config_name, "peer_b", FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2)
        configs = list(wg.generate_configs())
        assert len(configs) == 2


# ===================================================================
# Address format permutations for config generators
# ===================================================================
_CIDR_PREFIXES = ["/8", "/16", "/24", "/32"]
_IPV4_BASES = ["10.0.0.1", "192.168.1.1", "172.16.0.1"]

class TestAddressPrefixPermutations:
    @pytest.mark.parametrize("base", _IPV4_BASES)
    @pytest.mark.parametrize("prefix", _CIDR_PREFIXES)
    def test_interface_config_address(self, base, prefix):
        addr = f"{base}{prefix}"
        cfg = generate_interface_config("n", "k", addr)
        assert f"Address = {addr}" in cfg

    @pytest.mark.parametrize("base", _IPV4_BASES)
    @pytest.mark.parametrize("prefix", _CIDR_PREFIXES)
    def test_mikrotik_interface_address(self, base, prefix):
        addr = f"{base}{prefix}"
        cfg = generate_mikrotik_interface_config("n", "k", [addr], "wg0")
        assert f"address={addr}" in cfg

    @pytest.mark.parametrize("base", _IPV4_BASES)
    @pytest.mark.parametrize("prefix", _CIDR_PREFIXES)
    def test_openwrt_interface_address(self, base, prefix):
        addr = f"{base}{prefix}"
        cfg = generate_openwrt_interface_config("n", "k", [addr], "wg0")
        assert f"list addresses '{addr}'" in cfg

    @pytest.mark.parametrize("base", _IPV4_BASES)
    @pytest.mark.parametrize("prefix", _CIDR_PREFIXES)
    def test_peer_allowed_ips(self, base, prefix):
        addr = f"{base}{prefix}"
        cfg = generate_peer_config("n", "pub", None, allowed_ips=[addr])
        assert addr in cfg


# ===================================================================
# Endpoint format tests across all generators
# ===================================================================
_ENDPOINT_FORMATS = [
    "1.2.3.4:51820",
    "10.0.0.1:1",
    "10.0.0.1:65535",
    "vpn.example.com:22781",
    "sub.domain.example.org:12345",
    "[::1]:51820",
    "[2001:db8::1]:51820",
    "host:0",
]

class TestEndpointFormats:
    @pytest.mark.parametrize("endpoint", _ENDPOINT_FORMATS)
    def test_wg_peer_endpoint(self, endpoint):
        cfg = generate_peer_config("n", "pub", None, endpoint=endpoint)
        assert f"Endpoint = {endpoint}" in cfg

    @pytest.mark.parametrize("endpoint", _ENDPOINT_FORMATS)
    def test_mikrotik_peer_endpoint(self, endpoint):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], "wg0",
            endpoint=endpoint, addresses=["10.0.0.2/24"]
        )
        addr, _, port = endpoint.rpartition(":")
        assert f"endpoint-address={addr}" in cfg
        assert f"endpoint-port={port}" in cfg

    @pytest.mark.parametrize("endpoint", _ENDPOINT_FORMATS)
    def test_openwrt_peer_endpoint(self, endpoint):
        cfg = generate_openwrt_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], "wg0",
            endpoint=endpoint
        )
        addr, _, port = endpoint.rpartition(":")
        assert f"option endpoint_host '{addr}'" in cfg
        assert f"option endpoint_port '{port}'" in cfg


# ===================================================================
# Network allocation exhaustive: many prefix lengths
# ===================================================================
class TestNetworkAllocationPrefixLengths:
    @pytest.mark.parametrize("prefix", [8, 16, 24, 28, 30])
    def test_collect_counters_prefix(self, prefix):
        addr = f"10.0.0.1/{prefix}"
        peers = [{"addresses": [addr]}]
        c = _collect_network_counters(peers)
        assert len(c[4]) == 1
        net = list(c[4].keys())[0]
        assert f"/{prefix}" in net

    @pytest.mark.parametrize("prefix", [24, 25, 26, 27, 28, 29, 30])
    def test_next_host_various_prefixes(self, prefix):
        net = ipaddress.ip_network(f"10.0.0.0/{prefix}")
        result = _next_host_in_network(net, [])
        if list(net.hosts()):
            assert result is not None
            assert f"/{prefix}" in result
        else:
            assert result is None

    @pytest.mark.parametrize("n_used,prefix", list(itertools.product([0, 1, 2, 5], [24, 25, 26])))
    def test_next_host_fill_levels(self, n_used, prefix):
        net = ipaddress.ip_network(f"10.0.0.0/{prefix}")
        hosts = list(net.hosts())
        peers = [{"addresses": [f"{hosts[i]}/{prefix}"]} for i in range(min(n_used, len(hosts)))]
        result = _next_host_in_network(net, peers)
        if n_used < len(hosts):
            assert result is not None
        else:
            assert result is None


# ===================================================================
# Keepalive parameterization across generators
# ===================================================================
class TestKeepaliveInConfigs:
    @pytest.mark.parametrize("keepalive", [0, 1, 10, 25, 30, 60, 120, 300, 65535])
    def test_wg_peer_keepalive(self, keepalive):
        cfg = generate_peer_config("n", "pub", None, keepalive=keepalive)
        assert f"PersistentKeepalive = {keepalive}" in cfg

    @pytest.mark.parametrize("keepalive", [0, 1, 10, 25, 30, 60, 120, 300, 65535])
    def test_mikrotik_peer_keepalive(self, keepalive):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], "wg0",
            keepalive=keepalive, addresses=["10.0.0.2/24"]
        )
        assert f"persistent-keepalive={keepalive}" in cfg

    @pytest.mark.parametrize("keepalive", [0, 1, 10, 25, 30, 60, 120, 300, 65535])
    def test_openwrt_peer_keepalive(self, keepalive):
        cfg = generate_openwrt_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], "wg0",
            keepalive=keepalive
        )
        assert f"option persistent_keepalive '{keepalive}'" in cfg


# ===================================================================
# add_device: various type permutations
# ===================================================================
class TestAddDeviceTypes:
    _TYPES = ["Server", "Client", "Router", "Mobile", "Desktop", "Notebook"]

    @pytest.mark.parametrize("type_name", _TYPES)
    def test_add_with_valid_type(self, tmp_dir, type_name):
        config = {
            "rules": {t: {"connect_to": ["*"], "keepalive": 30} for t in self._TYPES},
            "peers": [],
        }
        path = write_config(tmp_dir, config)
        add_device(path, f"dev_{type_name}", type=type_name,
                   addresses=["10.0.0.1/24"], provides_routes=[], yes=True)
        with open(path) as f:
            data = json.load(f)
        assert data["peers"][0]["type"] == type_name

    @pytest.mark.parametrize("invalid_type", ["Invalid", "Unknown", "", "SERVER", "server"])
    def test_add_with_invalid_type(self, tmp_dir, invalid_type):
        config = {"rules": {"Server": {"connect_to": ["*"]}}, "peers": []}
        path = write_config(tmp_dir, config)
        with pytest.raises(SystemExit):
            add_device(path, "dev", type=invalid_type, yes=True)


# ===================================================================
# rename_device: many scenarios
# ===================================================================
class TestRenameDeviceScenarios:
    @pytest.mark.parametrize("old_name,new_name", [
        ("peer1", "peer2"),
        ("a", "b"),
        ("very-long-name-here", "short"),
        ("peer.with.dots", "peer_with_underscores"),
        ("UPPER", "lower"),
    ])
    def test_rename_variants(self, tmp_dir, old_name, new_name):
        config = {"rules": {}, "peers": [{"name": old_name, "type": "Server"}]}
        path = write_config(tmp_dir, config)
        rename_device(path, old_name, new_name, yes=True)
        with open(path) as f:
            data = json.load(f)
        assert data["peers"][0]["name"] == new_name

    @pytest.mark.parametrize("old_name,new_name", [
        ("peer1", "peer2"),
        ("a", "b"),
    ])
    def test_rename_dry_run_no_change(self, tmp_dir, old_name, new_name):
        config = {"rules": {}, "peers": [{"name": old_name, "type": "Server"}]}
        path = write_config(tmp_dir, config)
        rename_device(path, old_name, new_name, yes=True, dry_run=True)
        with open(path) as f:
            data = json.load(f)
        assert data["peers"][0]["name"] == old_name  # unchanged


# ===================================================================
# format_json: various data shapes
# ===================================================================
class TestFormatJsonShapes:
    @pytest.mark.parametrize("config", [
        {"rules": {}, "peers": []},
        {"rules": {"A": {"keepalive": 30}}, "peers": [{"name": "p1"}]},
        {"rules": {"A": {}, "B": {}}, "peers": [{"name": "p1"}, {"name": "p2"}]},
        {"rules": {"A": {"connect_to": ["B", "C"], "keepalive": 30, "IPv6": True}},
         "peers": [{"name": "p1", "addresses": ["10.0.0.1/24", "fd00::1/64"],
                     "provides_routes": ["192.168.1.0/24"]}]},
    ])
    @pytest.mark.parametrize("indent", [2, 4])
    def test_format_preserves_data(self, tmp_dir, config, indent):
        path = os.path.join(tmp_dir, "test.json")
        with open(path, "w") as f:
            json.dump(config, f)  # compact
        format_json(path, indent=indent, yes=True)
        with open(path) as f:
            data = json.load(f)
        assert data == config


# ===================================================================
# list_clients: many configurations
# ===================================================================
class TestListClientsVaried:
    @pytest.mark.parametrize("n_clients", [0, 1, 5, 10, 20])
    def test_varying_client_counts(self, tmp_dir, capsys, n_clients):
        config = {
            "rules": {},
            "peers": [
                {"name": f"c{i}", "type": "Client", "addresses": [f"10.0.0.{i}/24"]}
                for i in range(n_clients)
            ],
        }
        path = write_config(tmp_dir, config)
        list_clients(path)
        captured = capsys.readouterr()
        for i in range(n_clients):
            assert f"c{i}" in captured.out

    @pytest.mark.parametrize("all_types", [True, False])
    def test_all_types_flag_variations(self, tmp_dir, capsys, all_types):
        config = {
            "rules": {},
            "peers": [
                {"name": "server1", "type": "Server", "addresses": ["10.0.0.1/24"]},
                {"name": "client1", "type": "Client", "addresses": ["10.0.0.2/24"]},
            ],
        }
        path = write_config(tmp_dir, config)
        list_clients(path, all_types=all_types)
        captured = capsys.readouterr()
        assert "client1" in captured.out
        if all_types:
            assert "server1" in captured.out
        else:
            assert "server1" not in captured.out


# ===================================================================
# Cross-format consistency: same config → all 3 formats
# ===================================================================
class TestCrossFormatConsistency:
    """Verify that generating all 3 formats for the same config doesn't error."""

    @pytest.mark.parametrize("n_peers", [1, 2, 3, 5])
    @pytest.mark.parametrize("has_routes", [True, False])
    @pytest.mark.parametrize("has_endpoint", [True, False])
    def test_all_formats(self, tmp_dir, n_peers, has_routes, has_endpoint):
        peers = []
        for i in range(n_peers):
            peer = {
                "name": f"p{i}",
                "type": "Server",
                "addresses": [f"10.0.0.{i+1}/24"],
            }
            if has_routes:
                peer["provides_routes"] = [f"192.168.{i}.0/24"]
            if has_endpoint:
                peer["endpoint"] = f"host{i}:{51820+i}"
            peers.append(peer)

        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": peers,
        }
        path = write_config(tmp_dir, config)
        wg = WireguardConfigurator(path)
        os.makedirs(wg.keys_dir, exist_ok=True)
        os.makedirs(wg.config_dir, exist_ok=True)
        os.makedirs(wg.mikrotik_dir, exist_ok=True)
        os.makedirs(wg.openwrt_dir, exist_ok=True)
        os.makedirs(wg.mobile_dir, exist_ok=True)
        keys = [(FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK),
                (FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2),
                (FAKE_PRIVKEY3, FAKE_PUBKEY3, FAKE_PSK3)]
        for i, peer in enumerate(peers):
            create_fake_keys(wg.config_name, peer["name"], *keys[i % 3])

        configs = list(wg.generate_configs())
        for ci in configs:
            wg.generate_wg_config(ci)
            wg.generate_mikrotik_config(ci)
            wg.generate_openwrt_config(ci)

        for ci in configs:
            name = ci.me.config["name"]
            assert os.path.isfile(os.path.join(wg.config_dir, f"{name}.conf"))
            assert os.path.isfile(os.path.join(wg.mikrotik_dir, f"{name}.mik"))
            assert os.path.isfile(os.path.join(wg.openwrt_dir, f"{name}.cfg"))


# ===================================================================
# Network counter: many peer counts
# ===================================================================
class TestNetworkCounterManyPeers:
    @pytest.mark.parametrize("n", [1, 2, 5, 10, 50, 100])
    def test_n_peers_same_network(self, n):
        peers = [{"addresses": [f"10.0.0.{i+1}/24"]} for i in range(n)]
        c = _collect_network_counters(peers)
        assert c[4]["10.0.0.0/24"] == n

    @pytest.mark.parametrize("n", [1, 2, 5, 10])
    def test_n_peers_different_networks(self, n):
        peers = [{"addresses": [f"10.{i}.0.1/24"]} for i in range(n)]
        c = _collect_network_counters(peers)
        assert len(c[4]) == n

    @pytest.mark.parametrize("n", [2, 3, 5])
    def test_select_most_common_of_n(self, n):
        # Make one network appear n times, others 1 time
        counter = Counter()
        counter["10.0.0.0/24"] = n
        for i in range(5):
            counter[f"192.168.{i}.0/24"] = 1
        result = _select_most_common_network(counter)
        assert result == ipaddress.ip_network("10.0.0.0/24")


# ===================================================================
# IPv6 detection: boundary cases
# ===================================================================
class TestIPv6Boundaries:
    @pytest.mark.parametrize("addr", [
        "::1",
        "::",
        "::ffff:c0a8:101",
        "0::0",
        "::ffff:0:0",
        "fe80::1%25eth0",
        "2001:db8::8a2e:370:7334",
    ])
    def test_ipv6_boundary_addresses(self, addr):
        assert is_ipv6(addr) is True

    @pytest.mark.parametrize("addr", [
        "10.0.0.1",
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "1.1.1.1",
    ])
    def test_ipv4_boundary_addresses(self, addr):
        assert is_ipv6(addr) is False
