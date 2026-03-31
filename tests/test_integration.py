"""Integration tests using the actual example configs from the repository.
Tests end-to-end generation with PointToMultipoint and Site2Site configs."""
import os

import pytest

from guardmywire import (
    WireguardConfigurator,
    get_keepalive,
    should_connect_to,
    is_reachable,
    is_any_reachable,
)
from tests.conftest import (
    POINT_TO_MULTIPOINT_CONFIG,
    SITE2SITE_CONFIG,
    write_config,
    create_fake_keys,
    FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK,
    FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2,
    FAKE_PRIVKEY3, FAKE_PUBKEY3, FAKE_PSK3,
)


class TestPointToMultipointExample:
    """Validate behavior with the PointToMultipoint example config."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_dir):
        self.config = POINT_TO_MULTIPOINT_CONFIG
        self.path = write_config(tmp_dir, self.config, "PointToMultipoint.json")
        self.wg = WireguardConfigurator(self.path)
        os.makedirs(self.wg.keys_dir, exist_ok=True)
        os.makedirs(self.wg.config_dir, exist_ok=True)
        os.makedirs(self.wg.mikrotik_dir, exist_ok=True)
        os.makedirs(self.wg.openwrt_dir, exist_ok=True)
        os.makedirs(self.wg.mobile_dir, exist_ok=True)
        keysets = [
            (FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK),
            (FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2),
            (FAKE_PRIVKEY3, FAKE_PUBKEY3, FAKE_PSK3),
            (FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK),  # reuse for 4th
        ]
        for i, peer in enumerate(self.config["peers"]):
            create_fake_keys(self.wg.config_name, peer["name"], *keysets[i])

    def test_generates_4_configs(self):
        configs = list(self.wg.generate_configs())
        assert len(configs) == 4

    def test_router_name(self):
        configs = list(self.wg.generate_configs())
        names = [c.me.config["name"] for c in configs]
        assert "MyWireguardRouter" in names

    def test_router_has_3_peers(self):
        configs = list(self.wg.generate_configs())
        router = next(c for c in configs if c.me.config["name"] == "MyWireguardRouter")
        assert len(router.peers) == 3

    def test_notebook_has_1_peer(self):
        configs = list(self.wg.generate_configs())
        nb = next(c for c in configs if c.me.config["name"] == "MyNotebook")
        assert len(nb.peers) == 1
        assert nb.peers[0].name == "MyWireguardRouter"

    def test_second_notebook_has_1_peer(self):
        configs = list(self.wg.generate_configs())
        nb2 = next(c for c in configs if c.me.config["name"] == "MySecondNotebook")
        assert len(nb2.peers) == 1
        assert nb2.peers[0].name == "MyWireguardRouter"

    def test_desktop_has_1_peer(self):
        configs = list(self.wg.generate_configs())
        dt = next(c for c in configs if c.me.config["name"] == "MyDesktop")
        assert len(dt.peers) == 1
        assert dt.peers[0].name == "MyWireguardRouter"

    def test_router_listen_port(self):
        configs = list(self.wg.generate_configs())
        router = next(c for c in configs if c.me.config["name"] == "MyWireguardRouter")
        assert router.me.config["endpoint"] == "my-dyndns-addr.domain.tld:22781"

    def test_router_provides_routes(self):
        configs = list(self.wg.generate_configs())
        nb = next(c for c in configs if c.me.config["name"] == "MyNotebook")
        router_peer = nb.peers[0]
        assert "192.168.1.0/24" in router_peer.allowed_ips

    def test_notebook_allowed_ips_includes_address(self):
        configs = list(self.wg.generate_configs())
        router = next(c for c in configs if c.me.config["name"] == "MyWireguardRouter")
        nb_peer = next(p for p in router.peers if p.name == "MyNotebook")
        assert "10.178.212.2/32" in nb_peer.allowed_ips

    def test_wg_conf_generated(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_wg_config(ci)
        assert os.path.isfile(os.path.join(self.wg.config_dir, "MyWireguardRouter.conf"))
        assert os.path.isfile(os.path.join(self.wg.config_dir, "MyNotebook.conf"))

    def test_mikrotik_conf_generated(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_mikrotik_config(ci)
        assert os.path.isfile(os.path.join(self.wg.mikrotik_dir, "MyWireguardRouter.mik"))

    def test_openwrt_conf_generated(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_openwrt_config(ci)
        assert os.path.isfile(os.path.join(self.wg.openwrt_dir, "MyWireguardRouter.cfg"))

    def test_router_wg_conf_has_correct_listen_port(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_wg_config(ci)
        with open(os.path.join(self.wg.config_dir, "MyWireguardRouter.conf")) as f:
            content = f.read()
        assert "ListenPort = 22781" in content

    def test_notebook_wg_conf_has_no_listen_port(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_wg_config(ci)
        with open(os.path.join(self.wg.config_dir, "MyNotebook.conf")) as f:
            content = f.read()
        assert "ListenPort" not in content

    def test_router_wg_conf_has_3_peers(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_wg_config(ci)
        with open(os.path.join(self.wg.config_dir, "MyWireguardRouter.conf")) as f:
            content = f.read()
        assert content.count("[Peer]") == 3

    def test_notebook_wg_conf_has_1_peer(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_wg_config(ci)
        with open(os.path.join(self.wg.config_dir, "MyNotebook.conf")) as f:
            content = f.read()
        assert content.count("[Peer]") == 1

    def test_mikrotik_interface_name(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_mikrotik_config(ci)
        with open(os.path.join(self.wg.mikrotik_dir, "MyWireguardRouter.mik")) as f:
            content = f.read()
        assert "name=WGPointToMultipoint" in content

    def test_openwrt_interface_name(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_openwrt_config(ci)
        with open(os.path.join(self.wg.openwrt_dir, "MyWireguardRouter.cfg")) as f:
            content = f.read()
        assert "config interface 'WGPointToMultipoint'" in content

    def test_keepalive_values(self):
        rules = self.config["rules"]
        assert get_keepalive(rules, "Router") == 30
        assert get_keepalive(rules, "Mobile") == 120
        assert get_keepalive(rules, "Desktop") == 60
        assert get_keepalive(rules, "Notebook") == 30

    def test_connection_rules(self):
        rules = self.config["rules"]
        assert should_connect_to(rules, "Mobile", "Router") is True
        assert should_connect_to(rules, "Mobile", "Mobile") is False
        assert should_connect_to(rules, "Router", "Mobile") is True
        assert should_connect_to(rules, "Router", "Router") is True

    def test_router_is_reachable(self):
        router = self.config["peers"][0]
        assert is_reachable(router) is True

    def test_notebooks_not_reachable(self):
        for peer in self.config["peers"][1:3]:
            assert is_reachable(peer) is False


class TestSite2SiteExample:
    """Validate behavior with the Site2Site example config."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_dir):
        self.config = SITE2SITE_CONFIG
        self.path = write_config(tmp_dir, self.config, "Site2Site.json")
        self.wg = WireguardConfigurator(self.path)
        os.makedirs(self.wg.keys_dir, exist_ok=True)
        os.makedirs(self.wg.config_dir, exist_ok=True)
        os.makedirs(self.wg.mikrotik_dir, exist_ok=True)
        os.makedirs(self.wg.openwrt_dir, exist_ok=True)
        os.makedirs(self.wg.mobile_dir, exist_ok=True)
        create_fake_keys(self.wg.config_name, "office1.mydomain.org", FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK)
        create_fake_keys(self.wg.config_name, "office2.mydomain.org", FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2)

    def test_generates_2_configs(self):
        configs = list(self.wg.generate_configs())
        assert len(configs) == 2

    def test_office1_has_1_peer(self):
        configs = list(self.wg.generate_configs())
        o1 = next(c for c in configs if c.me.config["name"] == "office1.mydomain.org")
        assert len(o1.peers) == 1
        assert o1.peers[0].name == "office2.mydomain.org"

    def test_office2_has_1_peer(self):
        configs = list(self.wg.generate_configs())
        o2 = next(c for c in configs if c.me.config["name"] == "office2.mydomain.org")
        assert len(o2.peers) == 1
        assert o2.peers[0].name == "office1.mydomain.org"

    def test_office1_provides_routes_in_allowed_ips(self):
        configs = list(self.wg.generate_configs())
        o2 = next(c for c in configs if c.me.config["name"] == "office2.mydomain.org")
        o1_peer = o2.peers[0]
        assert "192.168.100.0/24" in o1_peer.allowed_ips

    def test_office2_provides_routes_in_allowed_ips(self):
        configs = list(self.wg.generate_configs())
        o1 = next(c for c in configs if c.me.config["name"] == "office1.mydomain.org")
        o2_peer = o1.peers[0]
        assert "192.168.200.0/24" in o2_peer.allowed_ips

    def test_wg_conf_generated_for_both(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_wg_config(ci)
        assert os.path.isfile(os.path.join(self.wg.config_dir, "office1.mydomain.org.conf"))
        assert os.path.isfile(os.path.join(self.wg.config_dir, "office2.mydomain.org.conf"))

    def test_mikrotik_conf_generated_for_both(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_mikrotik_config(ci)
        assert os.path.isfile(os.path.join(self.wg.mikrotik_dir, "office1.mydomain.org.mik"))
        assert os.path.isfile(os.path.join(self.wg.mikrotik_dir, "office2.mydomain.org.mik"))

    def test_openwrt_conf_generated_for_both(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_openwrt_config(ci)
        assert os.path.isfile(os.path.join(self.wg.openwrt_dir, "office1.mydomain.org.cfg"))
        assert os.path.isfile(os.path.join(self.wg.openwrt_dir, "office2.mydomain.org.cfg"))

    def test_office1_listen_port(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_wg_config(ci)
        with open(os.path.join(self.wg.config_dir, "office1.mydomain.org.conf")) as f:
            content = f.read()
        assert "ListenPort = 19628" in content

    def test_office2_no_listen_port(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_wg_config(ci)
        with open(os.path.join(self.wg.config_dir, "office2.mydomain.org.conf")) as f:
            content = f.read()
        assert "ListenPort" not in content

    def test_server_keepalive(self):
        assert get_keepalive(self.config["rules"], "Server") == 60

    def test_server_connects_to_all(self):
        assert should_connect_to(self.config["rules"], "Server", "Server") is True
        assert should_connect_to(self.config["rules"], "Server", "Anything") is True

    def test_office1_reachable(self):
        assert is_reachable(self.config["peers"][0]) is True

    def test_office2_not_reachable(self):
        assert is_reachable(self.config["peers"][1]) is False

    def test_offices_any_reachable(self):
        assert is_any_reachable(self.config["peers"][0], self.config["peers"][1]) is True

    def test_mikrotik_content(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_mikrotik_config(ci)
        with open(os.path.join(self.wg.mikrotik_dir, "office1.mydomain.org.mik")) as f:
            content = f.read()
        assert "name=wg0" in content
        assert "/interface wireguard peers add" in content

    def test_openwrt_content(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_openwrt_config(ci)
        with open(os.path.join(self.wg.openwrt_dir, "office1.mydomain.org.cfg")) as f:
            content = f.read()
        assert "config interface 'wg0'" in content
        assert "option proto 'wireguard'" in content

    def test_mikrotik_routes_for_office2(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_mikrotik_config(ci)
        with open(os.path.join(self.wg.mikrotik_dir, "office1.mydomain.org.mik")) as f:
            content = f.read()
        assert 'dst-address="192.168.200.0/24"' in content

    def test_mikrotik_routes_for_office1(self):
        for ci in self.wg.generate_configs():
            self.wg.generate_mikrotik_config(ci)
        with open(os.path.join(self.wg.mikrotik_dir, "office2.mydomain.org.mik")) as f:
            content = f.read()
        assert 'dst-address="192.168.100.0/24"' in content


class TestCustomConfigurations:
    """Test various custom configurations that exercise different code paths."""

    def _make_wg(self, tmp_dir, config, name="custom.json"):
        path = write_config(tmp_dir, config, name)
        wg = WireguardConfigurator(path)
        os.makedirs(wg.keys_dir, exist_ok=True)
        os.makedirs(wg.config_dir, exist_ok=True)
        os.makedirs(wg.mikrotik_dir, exist_ok=True)
        os.makedirs(wg.openwrt_dir, exist_ok=True)
        os.makedirs(wg.mobile_dir, exist_ok=True)
        for i, peer in enumerate(config["peers"]):
            if not peer.get("disabled"):
                keys = [(FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK),
                        (FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2),
                        (FAKE_PRIVKEY3, FAKE_PUBKEY3, FAKE_PSK3)]
                create_fake_keys(wg.config_name, peer["name"], *keys[i % 3])
        return wg

    @pytest.mark.parametrize("n_peers", [1, 2, 3, 5, 10])
    def test_varying_peer_counts(self, tmp_dir, n_peers):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": f"s{i}", "type": "Server", "addresses": [f"10.0.0.{i}/24"], "endpoint": f"h:{i}"}
                for i in range(1, n_peers + 1)
            ],
        }
        wg = self._make_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        assert len(configs) == n_peers
        for ci in configs:
            assert len(ci.peers) == n_peers - 1
            wg.generate_wg_config(ci)
            wg.generate_mikrotik_config(ci)
            wg.generate_openwrt_config(ci)

    def test_dual_stack_config(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "type": "Server", "addresses": ["10.0.0.1/24", "fd00::1/64"], "endpoint": "a:1"},
                {"name": "s2", "type": "Server", "addresses": ["10.0.0.2/24", "fd00::2/64"], "endpoint": "b:2"},
            ],
        }
        wg = self._make_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        s1 = next(c for c in configs if c.me.config["name"] == "s1")
        s2_peer = s1.peers[0]
        assert "10.0.0.2/32" in s2_peer.allowed_ips
        assert "fd00::2/128" in s2_peer.allowed_ips

    def test_hub_and_spoke_topology(self, tmp_dir):
        config = {
            "rules": {
                "Hub": {"connect_to": ["*"], "keepalive": 30},
                "Spoke": {"connect_to": ["Hub"], "keepalive": 60},
            },
            "peers": [
                {"name": "hub1", "type": "Hub", "addresses": ["10.0.0.1/24"], "endpoint": "hub:1"},
                {"name": "spoke1", "type": "Spoke", "addresses": ["10.0.0.2/24"]},
                {"name": "spoke2", "type": "Spoke", "addresses": ["10.0.0.3/24"]},
                {"name": "spoke3", "type": "Spoke", "addresses": ["10.0.0.4/24"]},
            ],
        }
        wg = self._make_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        hub = next(c for c in configs if c.me.config["name"] == "hub1")
        assert len(hub.peers) == 3
        for spoke_ci in [c for c in configs if c.me.config["name"].startswith("spoke")]:
            assert len(spoke_ci.peers) == 1
            assert spoke_ci.peers[0].name == "hub1"

    def test_use_psk_in_config_output(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "type": "Server", "addresses": ["10.0.0.1/24"],
                 "endpoint": "a:1", "use_psk": True},
                {"name": "s2", "type": "Server", "addresses": ["10.0.0.2/24"],
                 "endpoint": "b:2", "use_psk": True},
            ],
        }
        wg = self._make_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        for ci in configs:
            wg.generate_wg_config(ci)
        with open(os.path.join(wg.config_dir, "s1.conf")) as f:
            content = f.read()
        assert "PresharedKey" in content

    def test_no_psk_in_config_output(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "type": "Server", "addresses": ["10.0.0.1/24"],
                 "endpoint": "a:1", "use_psk": False},
                {"name": "s2", "type": "Server", "addresses": ["10.0.0.2/24"],
                 "endpoint": "b:2", "use_psk": False},
            ],
        }
        wg = self._make_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        for ci in configs:
            wg.generate_wg_config(ci)
        with open(os.path.join(wg.config_dir, "s1.conf")) as f:
            content = f.read()
        assert "PresharedKey" not in content

    def test_mixed_psk_config(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "type": "Server", "addresses": ["10.0.0.1/24"],
                 "endpoint": "a:1", "use_psk": True},
                {"name": "s2", "type": "Server", "addresses": ["10.0.0.2/24"],
                 "endpoint": "b:2", "use_psk": False},
            ],
        }
        wg = self._make_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        for ci in configs:
            wg.generate_wg_config(ci)
        # s1 sees s2 (no psk)
        with open(os.path.join(wg.config_dir, "s1.conf")) as f:
            content = f.read()
        assert "PresharedKey" not in content
        # s2 sees s1 (with psk)
        with open(os.path.join(wg.config_dir, "s2.conf")) as f:
            content = f.read()
        assert "PresharedKey" in content
