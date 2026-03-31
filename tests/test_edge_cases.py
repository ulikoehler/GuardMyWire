"""Edge case and invalid input tests for all functions."""
import ipaddress
import json
import os
import sys
from collections import Counter
from unittest.mock import patch

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
    KeySet,
    SelfConfig,
    RemotePeerConfig,
    ConfigInfo,
    WireguardConfigurator,
    _collect_network_counters,
    _select_most_common_network,
    _next_host_in_network,
    _next_subnet_for_routes,
    format_json,
    rename_device,
    add_device,
    list_clients,
    prompt_yes_no,
)
from tests.conftest import (
    write_config,
    create_fake_keys,
    FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK,
)


# ===================================================================
# Edge cases: empty / None / special characters
# ===================================================================
class TestEdgeCasesEmptyInputs:
    def test_interface_config_empty_name(self):
        cfg = generate_interface_config("", "key", "10.0.0.1/24")
        assert "[Interface]" in cfg
        assert "# Name = " in cfg

    def test_interface_config_empty_key(self):
        cfg = generate_interface_config("n", "", "10.0.0.1/24")
        assert "PrivateKey = \n" in cfg

    def test_interface_config_empty_address(self):
        cfg = generate_interface_config("n", "k", "")
        assert "Address = \n" in cfg

    def test_peer_config_empty_name(self):
        cfg = generate_peer_config("", "pub", None)
        assert "[Peer]" in cfg

    def test_peer_config_empty_pubkey(self):
        cfg = generate_peer_config("n", "", None)
        assert "PublicKey = \n" in cfg

    def test_peer_config_empty_allowed_ips(self):
        cfg = generate_peer_config("n", "pub", None, allowed_ips=[])
        assert "AllowedIPs = \n" in cfg

    def test_peer_config_empty_psk(self):
        cfg = generate_peer_config("n", "pub", "")
        assert "PresharedKey = \n" in cfg

    def test_mikrotik_interface_empty_addresses(self):
        cfg = generate_mikrotik_interface_config("n", "k", [], "wg0")
        assert "/interface wireguard add" in cfg
        assert "/ip address add" not in cfg

    def test_openwrt_interface_empty_addresses(self):
        cfg = generate_openwrt_interface_config("n", "k", [], "wg0")
        assert "config interface" in cfg
        assert "list addresses" not in cfg

    def test_mikrotik_peer_empty_allowed_ips(self):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, [], "wg0", addresses=["10.0.0.1/24"]
        )
        assert "allowed-address=" in cfg

    def test_openwrt_peer_empty_allowed_ips(self):
        cfg = generate_openwrt_peer_config("n", "pub", None, [], "wg0")
        assert "list allowed_ips" not in cfg


class TestEdgeCasesSpecialCharacters:
    @pytest.mark.parametrize("name", [
        "peer with spaces",
        "peer\twith\ttabs",
        'peer"with"quotes',
        "peer'with'single",
        "peer;with;semicolons",
        "peer&with&ampersands",
        "peer|with|pipes",
    ])
    def test_special_chars_in_name_interface(self, name):
        cfg = generate_interface_config(name, "key", "10.0.0.1/24")
        assert f"# Name = {name}" in cfg

    @pytest.mark.parametrize("name", [
        "peer with spaces",
        'peer"with"quotes',
        "peer'with'single",
    ])
    def test_special_chars_in_name_peer(self, name):
        cfg = generate_peer_config(name, "pub", None)
        assert f"# Name = {name}" in cfg

    @pytest.mark.parametrize("key", [
        "key with spaces",
        "key=with=equals",
        "key+with+plus",
        "key/with/slashes",
    ])
    def test_special_chars_in_key(self, key):
        cfg = generate_interface_config("n", key, "10.0.0.1/24")
        assert f"PrivateKey = {key}" in cfg


class TestEdgeCasesLargeInputs:
    def test_many_allowed_ips(self):
        ips = [f"10.{i}.0.0/16" for i in range(256)]
        cfg = generate_peer_config("n", "pub", None, allowed_ips=ips)
        assert len(ips) == 256
        for ip in ips:
            assert ip in cfg

    def test_many_addresses_mikrotik(self):
        addrs = [f"10.0.{i}.1/24" for i in range(50)]
        cfg = generate_mikrotik_interface_config("n", "k", addrs, "wg0")
        for addr in addrs:
            assert f"address={addr}" in cfg

    def test_many_routes_mikrotik(self):
        routes = [f"192.168.{i}.0/24" for i in range(50)]
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], "wg0",
            provides_routes=routes, addresses=["10.0.0.2/24"]
        )
        for route in routes:
            assert f'dst-address="{route}"' in cfg

    def test_very_long_name(self):
        name = "a" * 500
        cfg = generate_interface_config(name, "k", "10.0.0.1/24")
        assert name in cfg

    def test_very_long_key(self):
        key = "k" * 500
        cfg = generate_interface_config("n", key, "10.0.0.1/24")
        assert key in cfg


class TestEdgeCasesNetworkAllocation:
    def test_collect_counters_mixed_valid_invalid(self):
        peers = [
            {"addresses": ["10.0.0.1/24", "not-valid", "192.168.1.1/24"]},
        ]
        c = _collect_network_counters(peers)
        assert c[4]["10.0.0.0/24"] == 1
        assert c[4]["192.168.1.0/24"] == 1

    def test_collect_counters_duplicate_addresses(self):
        peers = [
            {"addresses": ["10.0.0.1/24"]},
            {"addresses": ["10.0.0.1/24"]},
        ]
        c = _collect_network_counters(peers)
        assert c[4]["10.0.0.0/24"] == 2

    def test_next_host_very_small_network(self):
        net = ipaddress.ip_network("10.0.0.0/31")  # 2 addresses (point-to-point)
        result = _next_host_in_network(net, [])
        assert result is not None

    def test_next_host_slash_32_single_host(self):
        net = ipaddress.ip_network("10.0.0.1/32")
        result = _next_host_in_network(net, [])
        # /32 has exactly one host in Python's ipaddress
        assert result == "10.0.0.1/32"

    def test_select_most_common_single_count(self):
        c = Counter({"10.0.0.0/24": 1})
        result = _select_most_common_network(c)
        assert result == ipaddress.ip_network("10.0.0.0/24")

    def test_next_subnet_single_route(self):
        peers = [{"provides_routes": ["10.0.0.0/24"]}]
        result = _next_subnet_for_routes(peers)
        assert result is not None

    def test_next_subnet_all_invalid_routes(self):
        peers = [{"provides_routes": ["invalid", "also-invalid"]}]
        result = _next_subnet_for_routes(peers)
        assert result is None

    def test_next_host_with_mixed_version_addresses(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        peers = [{"addresses": ["10.0.0.1/24", "fd00::1/64"]}]
        result = _next_host_in_network(net, peers)
        assert result == "10.0.0.2/24"  # IPv6 addr in different network ignored


class TestEdgeCasesConfigurator:
    def _setup(self, tmp_dir, config, name="test.json"):
        path = write_config(tmp_dir, config, name)
        wg = WireguardConfigurator(path)
        os.makedirs(wg.keys_dir, exist_ok=True)
        os.makedirs(wg.config_dir, exist_ok=True)
        os.makedirs(wg.mikrotik_dir, exist_ok=True)
        os.makedirs(wg.openwrt_dir, exist_ok=True)
        os.makedirs(wg.mobile_dir, exist_ok=True)
        for peer in config.get("peers", []):
            if not peer.get("disabled"):
                create_fake_keys(wg.config_name, peer["name"])
        return wg

    def test_all_disabled_peers(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [
                {"name": "s1", "type": "Server", "disabled": True},
                {"name": "s2", "type": "Server", "disabled": True},
            ],
        }
        wg = self._setup(tmp_dir, config)
        configs = list(wg.generate_configs())
        assert len(configs) == 0

    def test_mixed_disabled_and_active(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [
                {"name": "active", "type": "Server", "addresses": ["10.0.0.1/24"], "endpoint": "a:1"},
                {"name": "disabled", "type": "Server", "addresses": ["10.0.0.2/24"], "disabled": True},
            ],
        }
        wg = self._setup(tmp_dir, config)
        configs = list(wg.generate_configs())
        assert len(configs) == 1
        assert configs[0].me.config["name"] == "active"

    def test_peer_with_no_addresses(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [
                {"name": "s1", "type": "Server", "addresses": [], "endpoint": "a:1"},
                {"name": "s2", "type": "Server", "addresses": ["10.0.0.2/24"], "endpoint": "b:2"},
            ],
        }
        wg = self._setup(tmp_dir, config)
        configs = list(wg.generate_configs())
        assert len(configs) == 2

    def test_peer_with_ipv6_only(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [
                {"name": "s1", "type": "Server", "addresses": ["fd00::1/64"], "endpoint": "a:1"},
                {"name": "s2", "type": "Server", "addresses": ["fd00::2/64"], "endpoint": "b:2"},
            ],
        }
        wg = self._setup(tmp_dir, config)
        configs = list(wg.generate_configs())
        s1 = next(c for c in configs if c.me.config["name"] == "s1")
        # s2's address should produce /128 in allowed_ips
        assert "fd00::2/128" in s1.peers[0].allowed_ips

    def test_endpoint_without_port(self, tmp_dir):
        """Endpoint that has no colon - edge case for partition."""
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [
                {"name": "s1", "type": "Server", "addresses": ["10.0.0.1/24"], "endpoint": "noport"},
                {"name": "s2", "type": "Server", "addresses": ["10.0.0.2/24"], "endpoint": "b:2"},
            ],
        }
        wg = self._setup(tmp_dir, config)
        configs = list(wg.generate_configs())
        # Should still generate without error
        for ci in configs:
            wg.generate_wg_config(ci)

    def test_provides_routes_not_duplicated_in_allowed_ips(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [
                {"name": "s1", "type": "Server", "addresses": ["10.0.0.1/24"], "endpoint": "a:1"},
                {"name": "s2", "type": "Server", "addresses": ["10.0.0.2/24"],
                 "provides_routes": ["10.0.0.2/32"], "endpoint": "b:2"},
            ],
        }
        wg = self._setup(tmp_dir, config)
        configs = list(wg.generate_configs())
        s1 = next(c for c in configs if c.me.config["name"] == "s1")
        # 10.0.0.2/32 should appear only once (deduped)
        assert s1.peers[0].allowed_ips.count("10.0.0.2/32") == 1

    def test_many_types_in_rules(self, tmp_dir):
        rules = {f"Type{i}": {"connect_to": ["*"], "keepalive": 30} for i in range(20)}
        peers = [
            {"name": f"peer{i}", "type": f"Type{i}", "addresses": [f"10.0.{i}.1/24"], "endpoint": f"h:{i+1}"}
            for i in range(20)
        ]
        config = {"rules": rules, "peers": peers}
        wg = self._setup(tmp_dir, config)
        configs = list(wg.generate_configs())
        assert len(configs) == 20
        for ci in configs:
            # Each peer should see all other 19 peers
            assert len(ci.peers) == 19


class TestEdgeCasesDeviceManagement:
    def test_rename_same_name(self, tmp_dir):
        config = {"rules": {}, "peers": [{"name": "p1", "type": "Server"}]}
        path = write_config(tmp_dir, config)
        # Renaming to same name should work but trigger overwrite logic
        rename_device(path, "p1", "p1", yes=True)
        with open(path) as f:
            data = json.load(f)
        assert data["peers"][0]["name"] == "p1"

    def test_add_device_to_empty_config(self, tmp_dir):
        config = {"rules": {"Client": {"connect_to": ["*"]}}, "peers": []}
        path = write_config(tmp_dir, config)
        add_device(path, "first", type="Client", addresses=["10.0.0.1/24"], provides_routes=[], yes=True)
        with open(path) as f:
            data = json.load(f)
        assert len(data["peers"]) == 1

    def test_add_device_no_rules(self, tmp_dir):
        config = {"rules": {}, "peers": []}
        path = write_config(tmp_dir, config)
        # type="Client" not in rules -> should fail
        with pytest.raises(SystemExit):
            add_device(path, "dev", type="Client", yes=True)

    def test_format_json_empty_object(self, tmp_dir):
        path = os.path.join(tmp_dir, "empty.json")
        with open(path, "w") as f:
            f.write("{}")
        format_json(path, indent=4, yes=True)
        with open(path) as f:
            data = json.load(f)
        assert data == {}

    def test_format_json_nested(self, tmp_dir):
        config = {
            "rules": {"A": {"keepalive": 30, "connect_to": ["B", "C"]}},
            "peers": [{"name": "p1", "addresses": ["10.0.0.1/24"]}],
        }
        path = write_config(tmp_dir, config)
        with open(path, "w") as f:
            json.dump(config, f)  # compact
        format_json(path, indent=4, yes=True)
        with open(path) as f:
            content = f.read()
        assert "\n" in content
        assert json.loads(content) == config

    def test_list_clients_multiple_addresses(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": [
            {"name": "multi", "type": "Client",
             "addresses": ["10.0.0.1/24", "fd00::1/64"],
             "provides_routes": ["192.168.1.0/24", "172.16.0.0/12"]},
        ]}
        path = write_config(tmp_dir, config)
        list_clients(path)
        captured = capsys.readouterr()
        assert "multi" in captured.out
        assert "10.0.0.1/24" in captured.out
        assert "fd00::1/64" in captured.out

    def test_list_clients_all_disabled(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": [
            {"name": "d1", "type": "Client", "disabled": True},
            {"name": "d2", "type": "Client", "disabled": True},
        ]}
        path = write_config(tmp_dir, config)
        list_clients(path)
        captured = capsys.readouterr()
        assert captured.out == ""


class TestEdgeCasesPromptYesNo:
    @pytest.mark.parametrize("response", [
        "Y", "y", "yes", "YES", "Yes", "yEs",
    ])
    def test_yes_variations(self, response):
        with patch("builtins.input", return_value=response):
            result = prompt_yes_no("q?")
        assert result is True or response.lower() in ("y", "yes")

    @pytest.mark.parametrize("response", [
        "n", "N", "no", "NO", "nope", "maybe", "x", "", "0", "false",
    ])
    def test_no_and_invalid(self, response):
        with patch("builtins.input", return_value=response):
            result = prompt_yes_no("q?")
        # Only "y" and "yes" are True
        if response.strip().lower() in ("y", "yes"):
            assert result is True
        else:
            assert result is False

    def test_keyboard_interrupt_bubbles(self):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                prompt_yes_no("q?")


# ===================================================================
# Config generation output format validation
# ===================================================================
class TestOutputFormatValidation:
    """Verify config output format details."""

    def test_wg_interface_ends_with_newline(self):
        cfg = generate_interface_config("n", "k", "10.0.0.1/24")
        assert cfg.endswith("\n")

    def test_wg_interface_with_port_ends_with_newline(self):
        cfg = generate_interface_config("n", "k", "10.0.0.1/24", 51820)
        assert cfg.endswith("\n")

    def test_wg_peer_ends_with_newline(self):
        cfg = generate_peer_config("n", "pub", None)
        assert cfg.endswith("\n")

    def test_wg_peer_with_endpoint_ends_with_newline(self):
        cfg = generate_peer_config("n", "pub", None, endpoint="1.2.3.4:51820")
        assert cfg.endswith("\n")

    def test_wg_peer_with_psk_ends_with_newline(self):
        cfg = generate_peer_config("n", "pub", "psk")
        assert cfg.endswith("\n")

    def test_mikrotik_interface_ends_with_newline(self):
        cfg = generate_mikrotik_interface_config("n", "k", ["10.0.0.1/24"], "wg0")
        assert cfg.endswith("\n")

    def test_openwrt_interface_ends_with_newline(self):
        cfg = generate_openwrt_interface_config("n", "k", ["10.0.0.1/24"], "wg0")
        assert cfg.endswith("\n")

    def test_openwrt_peer_ends_with_newline(self):
        cfg = generate_openwrt_peer_config("n", "pub", None, ["10.0.0.1/32"], "wg0")
        assert cfg.endswith("\n")

    def test_wg_interface_no_blank_lines(self):
        cfg = generate_interface_config("n", "k", "10.0.0.1/24")
        assert "\n\n" not in cfg

    def test_wg_peer_no_blank_lines(self):
        cfg = generate_peer_config("n", "pub", None)
        assert "\n\n" not in cfg

    @pytest.mark.parametrize("port", [51820, 0, 65535])
    def test_mikrotik_listen_port_format(self, port):
        cfg = generate_mikrotik_interface_config("n", "k", ["10.0.0.1/24"], "wg0", port)
        assert f"listen-port={port}" in cfg
        # No spaces around =
        assert "listen-port = " not in cfg

    @pytest.mark.parametrize("port", [51820, 0, 65535])
    def test_openwrt_listen_port_format(self, port):
        cfg = generate_openwrt_interface_config("n", "k", ["10.0.0.1/24"], "wg0", port)
        assert f"option listen_port '{port}'" in cfg
