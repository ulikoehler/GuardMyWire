"""Tests for WireGuard config generation functions:
generate_interface_config, generate_peer_config,
generate_mikrotik_interface_config, generate_mikrotik_peer_config,
generate_openwrt_interface_config, generate_openwrt_peer_config.

Heavy parameterization to cover all input combinations.
"""
import itertools
import pytest

from guardmywire import (
    generate_interface_config,
    generate_peer_config,
    generate_mikrotik_interface_config,
    generate_mikrotik_peer_config,
    generate_openwrt_interface_config,
    generate_openwrt_peer_config,
)


# ===================================================================
# Shared test data pools
# ===================================================================
NAMES = ["peer1", "MyRouter", "office1.mydomain.org", "名前", "peer with spaces", "a"]
PRIVATE_KEYS = [
    "cFakePrivKey00000000000000000000000000000000=",
    "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NQ==",
    "",
]
PUBLIC_KEYS = [
    "xFakePubKey000000000000000000000000000000000=",
    "UHVibGljS2V5QmFzZTY0RW5jb2RlZERhdGFIZXJl0=",
]
PSKS = [
    "pFakePSK0000000000000000000000000000000000000=",
    None,
]
ADDRESSES_SINGLE = [
    "10.0.0.1/24",
    "192.168.1.1/32",
    "172.16.0.1/16",
    "fd00::1/64",
    "10.178.212.1/24",
]
ADDRESSES_MULTI = [
    ["10.0.0.1/24"],
    ["10.0.0.1/24", "fd00::1/64"],
    ["192.168.1.1/32", "172.16.0.1/16", "10.0.0.3/24"],
]
LISTEN_PORTS = [None, 51820, 22781, 0, 1, 65535]
ENDPOINTS = [None, "1.2.3.4:51820", "vpn.example.com:22781", "[::1]:51820"]
KEEPALIVES = [0, 10, 30, 60, 120]
ALLOWED_IPS_LIST = [
    ["10.0.0.1/32"],
    ["10.0.0.0/24", "192.168.1.0/24"],
    ["0.0.0.0/0"],
    ["10.0.0.1/32", "fd00::1/128"],
    [],
]
ROUTE_LISTS = [
    [],
    ["192.168.1.0/24"],
    ["192.168.1.0/24", "172.16.0.0/12"],
]
INTERFACE_NAMES = ["wg0", "WGPointToMultipoint", "wireguard", None]


# ===================================================================
# generate_interface_config
# ===================================================================
class TestGenerateInterfaceConfig:
    """Standard WireGuard [Interface] block generation."""

    @pytest.mark.parametrize("name", NAMES)
    @pytest.mark.parametrize("listen_port", LISTEN_PORTS)
    def test_interface_name_in_comment(self, name, listen_port):
        cfg = generate_interface_config(name, "key", "10.0.0.1/24", listen_port)
        assert f"# Name = {name}" in cfg

    @pytest.mark.parametrize("private_key", PRIVATE_KEYS)
    def test_private_key_present(self, private_key):
        cfg = generate_interface_config("n", private_key, "10.0.0.1/24")
        assert f"PrivateKey = {private_key}" in cfg

    @pytest.mark.parametrize("address", ADDRESSES_SINGLE)
    def test_address_present(self, address):
        cfg = generate_interface_config("n", "k", address)
        assert f"Address = {address}" in cfg

    @pytest.mark.parametrize("listen_port", [51820, 22781, 1, 65535])
    def test_listen_port_present(self, listen_port):
        cfg = generate_interface_config("n", "k", "10.0.0.1/24", listen_port)
        assert f"ListenPort = {listen_port}" in cfg

    def test_no_listen_port(self):
        cfg = generate_interface_config("n", "k", "10.0.0.1/24", None)
        assert "ListenPort" not in cfg

    def test_zero_listen_port(self):
        cfg = generate_interface_config("n", "k", "10.0.0.1/24", 0)
        assert "ListenPort = 0" in cfg

    @pytest.mark.parametrize("name", NAMES)
    def test_starts_with_interface(self, name):
        cfg = generate_interface_config(name, "k", "10.0.0.1/24")
        assert cfg.strip().startswith("[Interface]")

    # Combinatorial: name × address × listen_port subset
    @pytest.mark.parametrize("name", NAMES[:3])
    @pytest.mark.parametrize("address", ADDRESSES_SINGLE[:3])
    @pytest.mark.parametrize("listen_port", [None, 51820])
    def test_combinatorial(self, name, address, listen_port):
        cfg = generate_interface_config(name, "k", address, listen_port)
        assert "[Interface]" in cfg
        assert f"Address = {address}" in cfg
        if listen_port is not None:
            assert f"ListenPort = {listen_port}" in cfg

    def test_multiline_address(self):
        addr = "10.0.0.1/24, fd00::1/64"
        cfg = generate_interface_config("n", "k", addr)
        assert f"Address = {addr}" in cfg

    def test_output_has_newlines(self):
        cfg = generate_interface_config("n", "k", "10.0.0.1/24")
        lines = cfg.strip().split("\n")
        assert len(lines) >= 3


# ===================================================================
# generate_peer_config
# ===================================================================
class TestGeneratePeerConfig:
    """Standard WireGuard [Peer] block generation."""

    @pytest.mark.parametrize("name", NAMES)
    def test_name_in_comment(self, name):
        cfg = generate_peer_config(name, "pubkey", None)
        assert f"# Name = {name}" in cfg

    @pytest.mark.parametrize("pubkey", PUBLIC_KEYS)
    def test_pubkey_present(self, pubkey):
        cfg = generate_peer_config("n", pubkey, None)
        assert f"PublicKey = {pubkey}" in cfg

    @pytest.mark.parametrize("psk", PSKS)
    def test_psk_handling(self, psk):
        cfg = generate_peer_config("n", "pub", psk)
        if psk is not None:
            assert f"PresharedKey = {psk}" in cfg
        else:
            assert "PresharedKey" not in cfg

    @pytest.mark.parametrize("allowed_ips", ALLOWED_IPS_LIST)
    def test_allowed_ips(self, allowed_ips):
        cfg = generate_peer_config("n", "pub", None, allowed_ips=allowed_ips)
        expected = ", ".join(allowed_ips)
        assert f"AllowedIPs = {expected}" in cfg

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    def test_endpoint_handling(self, endpoint):
        cfg = generate_peer_config("n", "pub", None, endpoint=endpoint)
        if endpoint is not None:
            assert f"Endpoint = {endpoint}" in cfg
        else:
            assert "Endpoint" not in cfg

    @pytest.mark.parametrize("keepalive", KEEPALIVES)
    def test_keepalive(self, keepalive):
        cfg = generate_peer_config("n", "pub", None, keepalive=keepalive)
        assert f"PersistentKeepalive = {keepalive}" in cfg

    def test_starts_with_peer(self):
        cfg = generate_peer_config("n", "pub", None)
        assert cfg.strip().startswith("[Peer]")

    # --- Combinatorial: name × pubkey × psk × endpoint × keepalive ---
    @pytest.mark.parametrize("name", NAMES[:3])
    @pytest.mark.parametrize("psk", PSKS)
    @pytest.mark.parametrize("endpoint", ENDPOINTS[:2])
    @pytest.mark.parametrize("keepalive", [10, 60])
    def test_combinatorial(self, name, psk, endpoint, keepalive):
        cfg = generate_peer_config(name, "pub", psk, allowed_ips=["10.0.0.1/32"], endpoint=endpoint, keepalive=keepalive)
        assert "[Peer]" in cfg
        assert f"# Name = {name}" in cfg
        assert f"PersistentKeepalive = {keepalive}" in cfg

    # --- Combinatorial: allowed_ips × endpoint ---
    @pytest.mark.parametrize("allowed_ips", ALLOWED_IPS_LIST)
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    def test_allowed_ips_with_endpoint(self, allowed_ips, endpoint):
        cfg = generate_peer_config("n", "pub", None, allowed_ips=allowed_ips, endpoint=endpoint)
        assert "[Peer]" in cfg

    def test_default_keepalive(self):
        cfg = generate_peer_config("n", "pub", None)
        assert "PersistentKeepalive = 10" in cfg


# ===================================================================
# generate_mikrotik_interface_config
# ===================================================================
class TestGenerateMikrotikInterfaceConfig:
    @pytest.mark.parametrize("name", NAMES[:4])
    @pytest.mark.parametrize("interface_name", INTERFACE_NAMES)
    @pytest.mark.parametrize("listen_port", [None, 51820])
    def test_basic_generation(self, name, interface_name, listen_port):
        cfg = generate_mikrotik_interface_config(
            name, "privkey", ["10.0.0.1/24"], interface_name, listen_port
        )
        effective_name = interface_name if interface_name is not None else name
        assert f"name={effective_name}" in cfg
        assert f"comment={name}" in cfg
        assert 'private-key="privkey"' in cfg
        if listen_port is not None:
            assert f"listen-port={listen_port}" in cfg

    @pytest.mark.parametrize("addresses", ADDRESSES_MULTI)
    def test_addresses_as_ip_commands(self, addresses):
        cfg = generate_mikrotik_interface_config("n", "k", addresses, "wg0")
        for addr in addresses:
            assert f"address={addr}" in cfg

    def test_no_listen_port(self):
        cfg = generate_mikrotik_interface_config("n", "k", ["10.0.0.1/24"], "wg0", None)
        assert "listen-port" not in cfg

    @pytest.mark.parametrize("listen_port", [0, 1, 65535, 51820])
    def test_listen_port_values(self, listen_port):
        cfg = generate_mikrotik_interface_config("n", "k", ["10.0.0.1/24"], "wg0", listen_port)
        assert f"listen-port={listen_port}" in cfg

    def test_mtu_1420(self):
        cfg = generate_mikrotik_interface_config("n", "k", ["10.0.0.1/24"], "wg0")
        assert "mtu=1420" in cfg

    def test_interface_wireguard_add(self):
        cfg = generate_mikrotik_interface_config("n", "k", ["10.0.0.1/24"], "wg0")
        assert cfg.startswith("/interface wireguard add")

    def test_ip_address_add(self):
        cfg = generate_mikrotik_interface_config("n", "k", ["10.0.0.1/24"], "wg0")
        assert "/ip address add" in cfg

    @pytest.mark.parametrize("address,expected_network", [
        ("10.0.0.1/24", "10.0.0.0"),
        ("192.168.1.100/24", "192.168.1.0"),
        ("172.16.0.1/16", "172.16.0.0"),
        ("10.0.0.1/32", "10.0.0.1"),
        ("10.178.212.1/24", "10.178.212.0"),
    ])
    def test_network_calculation(self, address, expected_network):
        cfg = generate_mikrotik_interface_config("n", "k", [address], "wg0")
        assert f"network={expected_network}" in cfg

    @pytest.mark.parametrize("name,interface_name", [
        ("MyRouter", None),
        ("MyRouter", "wg0"),
    ])
    def test_interface_name_fallback(self, name, interface_name):
        cfg = generate_mikrotik_interface_config(name, "k", ["10.0.0.1/24"], interface_name)
        expected = interface_name if interface_name is not None else name
        assert f"name={expected}" in cfg

    # Combinatorial: addresses × interface_name × listen_port
    @pytest.mark.parametrize("addresses", ADDRESSES_MULTI)
    @pytest.mark.parametrize("interface_name", INTERFACE_NAMES[:2])
    @pytest.mark.parametrize("listen_port", [None, 51820])
    def test_combinatorial(self, addresses, interface_name, listen_port):
        cfg = generate_mikrotik_interface_config("n", "k", addresses, interface_name, listen_port)
        assert "/interface wireguard add" in cfg


# ===================================================================
# generate_mikrotik_peer_config
# ===================================================================
class TestGenerateMikrotikPeerConfig:
    @pytest.mark.parametrize("name", NAMES[:3])
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    @pytest.mark.parametrize("keepalive", [None, 30, 60])
    def test_basic_generation(self, name, endpoint, keepalive):
        cfg = generate_mikrotik_peer_config(
            name, "pubkey", "psk", ["10.0.0.1/32"], "wg0",
            endpoint=endpoint, keepalive=keepalive,
            addresses=["10.0.0.2/24"]
        )
        assert f'comment="{name}"' in cfg
        assert 'public-key="pubkey"' in cfg

    @pytest.mark.parametrize("allowed_ips", ALLOWED_IPS_LIST)
    def test_allowed_ips(self, allowed_ips):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, allowed_ips, "wg0", addresses=["10.0.0.1/24"]
        )
        assert f"allowed-address={','.join(allowed_ips)}" in cfg

    @pytest.mark.parametrize("psk", PSKS)
    def test_psk_handling(self, psk):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", psk, ["10.0.0.1/32"], "wg0", addresses=["10.0.0.1/24"]
        )
        if psk is not None:
            assert f'preshared-key="{psk}"' in cfg
        else:
            assert "preshared-key" not in cfg

    @pytest.mark.parametrize("endpoint", [
        "1.2.3.4:51820",
        "vpn.example.com:22781",
    ])
    def test_endpoint_parsing(self, endpoint):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], "wg0",
            endpoint=endpoint, addresses=["10.0.0.1/24"]
        )
        addr, _, port = endpoint.rpartition(":")
        assert f"endpoint-address={addr}" in cfg
        assert f"endpoint-port={port}" in cfg

    def test_no_endpoint(self):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], "wg0", addresses=["10.0.0.1/24"]
        )
        assert "endpoint-address" not in cfg
        assert "endpoint-port" not in cfg

    @pytest.mark.parametrize("keepalive", [None, 0, 30, 60, 120])
    def test_keepalive_handling(self, keepalive):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], "wg0",
            keepalive=keepalive, addresses=["10.0.0.1/24"]
        )
        if keepalive is not None:
            assert f"persistent-keepalive={keepalive}" in cfg
        else:
            assert "persistent-keepalive" not in cfg

    @pytest.mark.parametrize("routes", ROUTE_LISTS)
    def test_routes(self, routes):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], "wg0",
            provides_routes=routes, addresses=["10.0.0.2/24"]
        )
        for route in routes:
            assert f'dst-address="{route}"' in cfg
            assert 'gateway="10.0.0.2"' in cfg
            assert 'check-gateway="ping"' in cfg

    def test_route_gateway_uses_first_address(self):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], "wg0",
            provides_routes=["192.168.1.0/24"],
            addresses=["10.0.0.5/24", "10.0.0.6/24"]
        )
        assert 'gateway="10.0.0.5"' in cfg

    @pytest.mark.parametrize("interface_name", ["wg0", "WGPointToMultipoint", "wireguard"])
    def test_interface_name(self, interface_name):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", None, ["10.0.0.1/32"], interface_name,
            addresses=["10.0.0.1/24"]
        )
        assert f"interface={interface_name}" in cfg

    # Combinatorial: endpoint × psk × routes
    @pytest.mark.parametrize("endpoint", ENDPOINTS[:2])
    @pytest.mark.parametrize("psk", PSKS)
    @pytest.mark.parametrize("routes", ROUTE_LISTS)
    def test_combinatorial(self, endpoint, psk, routes):
        cfg = generate_mikrotik_peer_config(
            "n", "pub", psk, ["10.0.0.1/32"], "wg0",
            endpoint=endpoint, provides_routes=routes,
            addresses=["10.0.0.1/24"]
        )
        assert "/interface wireguard peers add" in cfg


# ===================================================================
# generate_openwrt_interface_config
# ===================================================================
class TestGenerateOpenwrtInterfaceConfig:
    @pytest.mark.parametrize("name", NAMES[:4])
    @pytest.mark.parametrize("interface_name", INTERFACE_NAMES)
    @pytest.mark.parametrize("listen_port", [None, 51820])
    def test_basic_generation(self, name, interface_name, listen_port):
        cfg = generate_openwrt_interface_config(
            name, "privkey", ["10.0.0.1/24"], interface_name, listen_port
        )
        effective_name = interface_name if interface_name is not None else name
        assert f"config interface '{effective_name}'" in cfg
        assert "option proto 'wireguard'" in cfg
        assert f"option private_key 'privkey'" in cfg

    @pytest.mark.parametrize("addresses", ADDRESSES_MULTI)
    def test_addresses(self, addresses):
        cfg = generate_openwrt_interface_config("n", "k", addresses, "wg0")
        for addr in addresses:
            assert f"list addresses '{addr}'" in cfg

    @pytest.mark.parametrize("listen_port", [51820, 22781, 1, 65535])
    def test_listen_port(self, listen_port):
        cfg = generate_openwrt_interface_config("n", "k", ["10.0.0.1/24"], "wg0", listen_port)
        assert f"option listen_port '{listen_port}'" in cfg

    def test_no_listen_port(self):
        cfg = generate_openwrt_interface_config("n", "k", ["10.0.0.1/24"], "wg0")
        assert "listen_port" not in cfg

    def test_interface_name_fallback(self):
        cfg = generate_openwrt_interface_config("MyRouter", "k", ["10.0.0.1/24"], None)
        assert "config interface 'MyRouter'" in cfg

    # Combinatorial
    @pytest.mark.parametrize("addresses", ADDRESSES_MULTI)
    @pytest.mark.parametrize("interface_name", INTERFACE_NAMES[:2])
    @pytest.mark.parametrize("listen_port", [None, 51820])
    def test_combinatorial(self, addresses, interface_name, listen_port):
        cfg = generate_openwrt_interface_config("n", "k", addresses, interface_name, listen_port)
        assert "config interface" in cfg
        assert "option proto 'wireguard'" in cfg


# ===================================================================
# generate_openwrt_peer_config
# ===================================================================
class TestGenerateOpenwrtPeerConfig:
    @pytest.mark.parametrize("name", NAMES[:3])
    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    @pytest.mark.parametrize("keepalive", [30, 60])
    def test_basic_generation(self, name, endpoint, keepalive):
        cfg = generate_openwrt_peer_config(
            name, "pubkey", "psk", ["10.0.0.1/32"], "wg0",
            endpoint=endpoint, keepalive=keepalive
        )
        assert f"option description '{name}'" in cfg
        assert f"option public_key 'pubkey'" in cfg
        assert f"option persistent_keepalive '{keepalive}'" in cfg

    @pytest.mark.parametrize("allowed_ips", ALLOWED_IPS_LIST)
    def test_allowed_ips(self, allowed_ips):
        cfg = generate_openwrt_peer_config(
            "n", "pub", None, allowed_ips, "wg0"
        )
        for ip in allowed_ips:
            assert f"list allowed_ips '{ip}'" in cfg

    @pytest.mark.parametrize("endpoint", [
        "1.2.3.4:51820",
        "vpn.example.com:22781",
    ])
    def test_endpoint_parsing(self, endpoint):
        cfg = generate_openwrt_peer_config("n", "pub", None, ["10.0.0.1/32"], "wg0", endpoint=endpoint)
        addr, _, port = endpoint.rpartition(":")
        assert f"option endpoint_host '{addr}'" in cfg
        assert f"option endpoint_port '{port}'" in cfg

    def test_no_endpoint(self):
        cfg = generate_openwrt_peer_config("n", "pub", None, ["10.0.0.1/32"], "wg0")
        assert "endpoint_host" not in cfg
        assert "endpoint_port" not in cfg

    @pytest.mark.parametrize("interface_name", ["wg0", "WGPointToMultipoint"])
    def test_interface_name_in_section(self, interface_name):
        cfg = generate_openwrt_peer_config("n", "pub", None, ["10.0.0.1/32"], interface_name)
        assert f"config wireguard_{interface_name}" in cfg

    def test_route_allowed_ips_option(self):
        cfg = generate_openwrt_peer_config("n", "pub", None, ["10.0.0.1/32"], "wg0")
        assert "option route_allowed_ips '1'" in cfg

    # Combinatorial
    @pytest.mark.parametrize("endpoint", ENDPOINTS[:2])
    @pytest.mark.parametrize("allowed_ips", ALLOWED_IPS_LIST[:3])
    @pytest.mark.parametrize("keepalive", [30, 60])
    def test_combinatorial(self, endpoint, allowed_ips, keepalive):
        cfg = generate_openwrt_peer_config(
            "n", "pub", "psk", allowed_ips, "wg0",
            endpoint=endpoint, keepalive=keepalive
        )
        assert "config wireguard_wg0" in cfg
