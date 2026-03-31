"""Tests for network allocation helpers:
_collect_network_counters, _select_most_common_network,
_next_host_in_network, _next_subnet_for_routes.
"""
import ipaddress
from collections import Counter

import pytest

from guardmywire import (
    _collect_network_counters,
    _select_most_common_network,
    _next_host_in_network,
    _next_subnet_for_routes,
)


# ===================================================================
# _collect_network_counters
# ===================================================================
class TestCollectNetworkCounters:
    def test_empty_peers(self):
        c = _collect_network_counters([])
        assert c[4] == Counter()
        assert c[6] == Counter()

    def test_single_ipv4(self):
        peers = [{"addresses": ["10.0.0.1/24"]}]
        c = _collect_network_counters(peers)
        assert c[4]["10.0.0.0/24"] == 1
        assert len(c[6]) == 0

    def test_single_ipv6(self):
        peers = [{"addresses": ["fd00::1/64"]}]
        c = _collect_network_counters(peers)
        assert c[6]["fd00::/64"] == 1
        assert len(c[4]) == 0

    def test_mixed_v4_v6(self):
        peers = [{"addresses": ["10.0.0.1/24", "fd00::1/64"]}]
        c = _collect_network_counters(peers)
        assert c[4]["10.0.0.0/24"] == 1
        assert c[6]["fd00::/64"] == 1

    def test_multiple_peers_same_network(self):
        peers = [
            {"addresses": ["10.0.0.1/24"]},
            {"addresses": ["10.0.0.2/24"]},
            {"addresses": ["10.0.0.3/24"]},
        ]
        c = _collect_network_counters(peers)
        assert c[4]["10.0.0.0/24"] == 3

    def test_multiple_different_networks(self):
        peers = [
            {"addresses": ["10.0.0.1/24"]},
            {"addresses": ["192.168.1.1/24"]},
        ]
        c = _collect_network_counters(peers)
        assert c[4]["10.0.0.0/24"] == 1
        assert c[4]["192.168.1.0/24"] == 1

    def test_peers_without_addresses(self):
        peers = [{"name": "peer1"}]
        c = _collect_network_counters(peers)
        assert c[4] == Counter()

    def test_empty_addresses(self):
        peers = [{"addresses": []}]
        c = _collect_network_counters(peers)
        assert c[4] == Counter()

    def test_invalid_address_skipped(self):
        peers = [{"addresses": ["not-an-address"]}]
        c = _collect_network_counters(peers)
        assert c[4] == Counter()
        assert c[6] == Counter()

    @pytest.mark.parametrize("addr,network,version", [
        ("10.0.0.1/24", "10.0.0.0/24", 4),
        ("10.0.0.1/32", "10.0.0.1/32", 4),
        ("10.0.0.1/16", "10.0.0.0/16", 4),
        ("172.16.5.10/12", "172.16.0.0/12", 4),
        ("192.168.1.100/24", "192.168.1.0/24", 4),
        ("fd00::1/64", "fd00::/64", 6),
        ("fd00::abcd/128", "fd00::abcd/128", 6),
    ])
    def test_network_calculation(self, addr, network, version):
        peers = [{"addresses": [addr]}]
        c = _collect_network_counters(peers)
        assert c[version][network] == 1

    def test_point_to_multipoint_example(self):
        peers = [
            {"addresses": ["10.178.212.1/24"]},
            {"addresses": ["10.178.212.2/24"]},
            {"addresses": ["10.178.212.3/24"]},
            {"addresses": ["10.178.212.4/24"]},
        ]
        c = _collect_network_counters(peers)
        assert c[4]["10.178.212.0/24"] == 4

    def test_site2site_example(self):
        peers = [
            {"addresses": ["10.82.85.1/24"]},
            {"addresses": ["10.82.85.2/24"]},
        ]
        c = _collect_network_counters(peers)
        assert c[4]["10.82.85.0/24"] == 2


# ===================================================================
# _select_most_common_network
# ===================================================================
class TestSelectMostCommonNetwork:
    def test_empty_counter(self):
        assert _select_most_common_network(Counter()) is None

    def test_single_entry(self):
        c = Counter({"10.0.0.0/24": 3})
        net = _select_most_common_network(c)
        assert net == ipaddress.ip_network("10.0.0.0/24")

    def test_multiple_entries_picks_most_common(self):
        c = Counter({"10.0.0.0/24": 5, "192.168.1.0/24": 2})
        net = _select_most_common_network(c)
        assert net == ipaddress.ip_network("10.0.0.0/24")

    def test_ipv6_network(self):
        c = Counter({"fd00::/64": 3})
        net = _select_most_common_network(c)
        assert net == ipaddress.ip_network("fd00::/64")

    @pytest.mark.parametrize("network_str", [
        "10.0.0.0/24",
        "192.168.0.0/16",
        "172.16.0.0/12",
        "10.0.0.0/8",
        "fd00::/64",
        "2001:db8::/32",
    ])
    def test_various_networks(self, network_str):
        c = Counter({network_str: 1})
        net = _select_most_common_network(c)
        assert net == ipaddress.ip_network(network_str)

    def test_tied_counts(self):
        c = Counter({"10.0.0.0/24": 2, "192.168.1.0/24": 2})
        net = _select_most_common_network(c)
        # Should return one of them (most_common picks first inserted on tie in recent Python)
        assert net in (ipaddress.ip_network("10.0.0.0/24"), ipaddress.ip_network("192.168.1.0/24"))


# ===================================================================
# _next_host_in_network
# ===================================================================
class TestNextHostInNetwork:
    def test_first_host_available(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        result = _next_host_in_network(net, [])
        assert result == "10.0.0.1/24"

    def test_first_host_taken(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        peers = [{"addresses": ["10.0.0.1/24"]}]
        result = _next_host_in_network(net, peers)
        assert result == "10.0.0.2/24"

    def test_multiple_hosts_taken(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        peers = [
            {"addresses": ["10.0.0.1/24"]},
            {"addresses": ["10.0.0.2/24"]},
            {"addresses": ["10.0.0.3/24"]},
        ]
        result = _next_host_in_network(net, peers)
        assert result == "10.0.0.4/24"

    def test_gap_in_addresses(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        peers = [
            {"addresses": ["10.0.0.1/24"]},
            {"addresses": ["10.0.0.3/24"]},  # gap at .2
        ]
        result = _next_host_in_network(net, peers)
        assert result == "10.0.0.2/24"

    def test_network_fully_allocated(self):
        net = ipaddress.ip_network("10.0.0.0/30")  # 2 usable hosts
        peers = [
            {"addresses": ["10.0.0.1/30"]},
            {"addresses": ["10.0.0.2/30"]},
        ]
        result = _next_host_in_network(net, peers)
        assert result is None

    def test_slash_32_network(self):
        net = ipaddress.ip_network("10.0.0.1/32")
        # /32 has exactly one host in Python's ipaddress
        result = _next_host_in_network(net, [])
        assert result == "10.0.0.1/32"

    def test_peers_with_different_prefix(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        peers = [{"addresses": ["10.0.0.1/32"]}]  # different prefix but same IP
        result = _next_host_in_network(net, peers)
        assert result == "10.0.0.2/24"

    def test_peers_in_different_network(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        peers = [{"addresses": ["192.168.1.1/24"]}]  # different network
        result = _next_host_in_network(net, peers)
        assert result == "10.0.0.1/24"

    def test_ipv6_network(self):
        net = ipaddress.ip_network("fd00::/126")  # 3 usable hosts
        result = _next_host_in_network(net, [])
        assert result == "fd00::1/126"

    def test_ipv6_with_used(self):
        net = ipaddress.ip_network("fd00::/126")
        peers = [{"addresses": ["fd00::1/126"]}]
        result = _next_host_in_network(net, peers)
        assert result == "fd00::2/126"

    def test_peers_without_addresses(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        peers = [{"name": "peer1"}]
        result = _next_host_in_network(net, peers)
        assert result == "10.0.0.1/24"

    def test_invalid_address_in_peers(self):
        net = ipaddress.ip_network("10.0.0.0/24")
        peers = [{"addresses": ["not-valid"]}]
        result = _next_host_in_network(net, peers)
        assert result == "10.0.0.1/24"

    @pytest.mark.parametrize("n_used", [0, 1, 5, 10, 50, 100, 200])
    def test_sequential_allocation(self, n_used):
        net = ipaddress.ip_network("10.0.0.0/24")
        peers = [{"addresses": [f"10.0.0.{i}/24"]} for i in range(1, n_used + 1)]
        result = _next_host_in_network(net, peers)
        if n_used < 254:
            assert result == f"10.0.0.{n_used + 1}/24"
        else:
            assert result is None

    def test_point_to_multipoint_scenario(self):
        net = ipaddress.ip_network("10.178.212.0/24")
        peers = [
            {"addresses": ["10.178.212.1/24"]},
            {"addresses": ["10.178.212.2/24"]},
            {"addresses": ["10.178.212.3/24"]},
            {"addresses": ["10.178.212.4/24"]},
        ]
        result = _next_host_in_network(net, peers)
        assert result == "10.178.212.5/24"


# ===================================================================
# _next_subnet_for_routes
# ===================================================================
class TestNextSubnetForRoutes:
    def test_no_routes(self):
        assert _next_subnet_for_routes([]) is None

    def test_no_provides_routes(self):
        peers = [{"name": "peer1"}]
        assert _next_subnet_for_routes(peers) is None

    def test_empty_provides_routes(self):
        peers = [{"provides_routes": []}]
        assert _next_subnet_for_routes(peers) is None

    def test_single_route(self):
        peers = [{"provides_routes": ["192.168.1.0/24"]}]
        result = _next_subnet_for_routes(peers)
        assert result is not None
        net = ipaddress.ip_network(result, strict=False)
        assert net.prefixlen == 24
        assert str(net) != "192.168.1.0/24"

    def test_sequential_routes(self):
        peers = [
            {"provides_routes": ["192.168.100.0/24"]},
            {"provides_routes": ["192.168.200.0/24"]},
        ]
        result = _next_subnet_for_routes(peers)
        assert result is not None
        net = ipaddress.ip_network(result, strict=False)
        assert net.prefixlen == 24
        # Should not be one of the existing routes
        assert str(net) not in ["192.168.100.0/24", "192.168.200.0/24"]

    def test_consecutive_routes_exhausted_supernet(self):
        # 10.0.0.0/24 and 10.0.1.0/24 fill the smallest supernet (10.0.0.0/23)
        peers = [
            {"provides_routes": ["10.0.0.0/24"]},
            {"provides_routes": ["10.0.1.0/24"]},
        ]
        result = _next_subnet_for_routes(peers)
        assert result is None

    def test_consecutive_routes_with_room(self):
        # 10.0.0.0/24 and 10.0.2.0/24 → supernet 10.0.0.0/22, has room
        peers = [
            {"provides_routes": ["10.0.0.0/24"]},
            {"provides_routes": ["10.0.2.0/24"]},
        ]
        result = _next_subnet_for_routes(peers)
        assert result is not None
        net = ipaddress.ip_network(result, strict=False)
        assert str(net) not in ["10.0.0.0/24", "10.0.2.0/24"]

    def test_invalid_route_skipped(self):
        peers = [
            {"provides_routes": ["not-valid"]},
            {"provides_routes": ["192.168.1.0/24"]},
        ]
        result = _next_subnet_for_routes(peers)
        assert result is not None

    def test_mixed_prefix_lengths(self):
        peers = [
            {"provides_routes": ["192.168.1.0/24"]},
            {"provides_routes": ["192.168.2.0/24"]},
            {"provides_routes": ["10.0.0.0/16"]},
        ]
        result = _next_subnet_for_routes(peers)
        assert result is not None
        # Most common prefix is /24
        net = ipaddress.ip_network(result, strict=False)
        assert net.prefixlen == 24

    def test_site2site_example(self):
        peers = [
            {"provides_routes": ["192.168.100.0/24"]},
            {"provides_routes": ["192.168.200.0/24"]},
        ]
        result = _next_subnet_for_routes(peers)
        assert result is not None
        net = ipaddress.ip_network(result, strict=False)
        assert net.prefixlen == 24

    @pytest.mark.parametrize("route", [
        "10.0.0.0/24",
        "172.16.0.0/16",
        "192.168.0.0/24",
    ])
    def test_single_route_returns_different(self, route):
        peers = [{"provides_routes": [route]}]
        result = _next_subnet_for_routes(peers)
        if result is not None:
            assert result != route

    def test_multiple_routes_per_peer(self):
        peers = [
            {"provides_routes": ["192.168.1.0/24", "192.168.2.0/24"]},
        ]
        result = _next_subnet_for_routes(peers)
        assert result is not None
