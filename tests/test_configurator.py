"""Tests for WireguardConfigurator class and generate_configs method.
Uses mocked subprocess and temp files to test end-to-end config generation."""
import json
import os
import shutil
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from guardmywire import (
    WireguardConfigurator,
    KeySet,
    SelfConfig,
    RemotePeerConfig,
    ConfigInfo,
    generate_or_load_peer_keys,
)
from tests.conftest import (
    FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK,
    FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2,
    FAKE_PRIVKEY3, FAKE_PUBKEY3, FAKE_PSK3,
    POINT_TO_MULTIPOINT_CONFIG,
    SITE2SITE_CONFIG,
    write_config,
    create_fake_keys,
)


# ===================================================================
# NamedTuple tests: SelfConfig, RemotePeerConfig, ConfigInfo
# ===================================================================
class TestSelfConfig:
    def test_creation(self):
        ks = KeySet("priv", "pub", "psk")
        sc = SelfConfig(config={"name": "peer1"}, keys=ks)
        assert sc.config["name"] == "peer1"
        assert sc.keys.private_key == "priv"

    def test_tuple_access(self):
        ks = KeySet("priv", "pub", "psk")
        sc = SelfConfig(config={}, keys=ks)
        assert sc[0] == {}
        assert sc[1] == ks


class TestRemotePeerConfig:
    def test_creation(self):
        ks = KeySet("priv", "pub", "psk")
        rpc = RemotePeerConfig(
            name="peer1", endpoint="1.2.3.4:51820",
            provides_routes=["192.168.1.0/24"], addresses=["10.0.0.1/24"],
            allowed_ips=["10.0.0.1/32"], use_psk=True, keys=ks
        )
        assert rpc.name == "peer1"
        assert rpc.endpoint == "1.2.3.4:51820"
        assert rpc.use_psk is True

    def test_no_endpoint(self):
        ks = KeySet("priv", "pub", "psk")
        rpc = RemotePeerConfig(
            name="peer1", endpoint=None,
            provides_routes=[], addresses=["10.0.0.1/24"],
            allowed_ips=["10.0.0.1/32"], use_psk=False, keys=ks
        )
        assert rpc.endpoint is None
        assert rpc.use_psk is False


class TestConfigInfo:
    def test_creation(self):
        ks = KeySet("priv", "pub", "psk")
        me = SelfConfig(config={"name": "me"}, keys=ks)
        ci = ConfigInfo(me=me, peers=[])
        assert ci.me.config["name"] == "me"
        assert ci.peers == []

    def test_with_peers(self):
        ks = KeySet("priv", "pub", "psk")
        me = SelfConfig(config={"name": "me"}, keys=ks)
        peer = RemotePeerConfig(
            name="p", endpoint=None, provides_routes=[],
            addresses=["10.0.0.2/24"], allowed_ips=["10.0.0.2/32"],
            use_psk=False, keys=ks
        )
        ci = ConfigInfo(me=me, peers=[peer])
        assert len(ci.peers) == 1


# ===================================================================
# WireguardConfigurator.__init__
# ===================================================================
class TestWireguardConfiguratorInit:
    def test_init_point_to_multipoint(self, p2mp_config_file):
        wg = WireguardConfigurator(p2mp_config_file)
        assert len(wg.peers) == 4
        assert "Router" in wg.rules
        assert "Mobile" in wg.rules
        assert wg.config_name == os.path.splitext(p2mp_config_file)[0]

    def test_init_site2site(self, s2s_config_file):
        wg = WireguardConfigurator(s2s_config_file)
        assert len(wg.peers) == 2
        assert "Server" in wg.rules

    def test_init_nonexistent_file(self, tmp_dir):
        with pytest.raises(FileNotFoundError):
            WireguardConfigurator(os.path.join(tmp_dir, "nonexistent.json"))

    def test_init_invalid_json(self, tmp_dir):
        path = os.path.join(tmp_dir, "invalid.json")
        with open(path, "w") as f:
            f.write("not json")
        with pytest.raises(json.JSONDecodeError):
            WireguardConfigurator(path)

    def test_init_missing_peers_key(self, tmp_dir):
        path = write_config(tmp_dir, {"rules": {}}, "nopeer.json")
        with pytest.raises(KeyError):
            WireguardConfigurator(path)

    def test_init_missing_rules_key(self, tmp_dir):
        path = write_config(tmp_dir, {"peers": []}, "norules.json")
        with pytest.raises(KeyError):
            WireguardConfigurator(path)

    def test_directory_names(self, p2mp_config_file):
        wg = WireguardConfigurator(p2mp_config_file)
        assert wg.keys_dir.endswith("keys")
        assert wg.config_dir.endswith("config")
        assert wg.mikrotik_dir.endswith("mikrotik")
        assert wg.openwrt_dir.endswith("openwrt")
        assert wg.mobile_dir.endswith("mobile")


# ===================================================================
# WireguardConfigurator.generate_configs
# ===================================================================
class TestGenerateConfigs:
    """Integration tests for the generate_configs generator method."""

    def _setup_wg(self, tmp_dir, config, config_name="test.json"):
        path = write_config(tmp_dir, config, config_name)
        wg = WireguardConfigurator(path)
        # Pre-create keys for all peers
        os.makedirs(wg.keys_dir, exist_ok=True)
        keys = [
            (FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK),
            (FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2),
            (FAKE_PRIVKEY3, FAKE_PUBKEY3, FAKE_PSK3),
        ]
        for i, peer in enumerate(config["peers"]):
            if peer.get("disabled"):
                continue
            k = keys[i % len(keys)]
            create_fake_keys(wg.config_name, peer["name"], *k)
        return wg

    def test_p2mp_yields_all_peers(self, tmp_dir):
        wg = self._setup_wg(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        configs = list(wg.generate_configs())
        assert len(configs) == 4
        names = [c.me.config["name"] for c in configs]
        assert "MyWireguardRouter" in names
        assert "MyNotebook" in names
        assert "MySecondNotebook" in names
        assert "MyDesktop" in names

    def test_s2s_yields_all_peers(self, tmp_dir):
        wg = self._setup_wg(tmp_dir, SITE2SITE_CONFIG)
        configs = list(wg.generate_configs())
        assert len(configs) == 2
        names = [c.me.config["name"] for c in configs]
        assert "office1.mydomain.org" in names
        assert "office2.mydomain.org" in names

    def test_p2mp_router_sees_all_peers(self, tmp_dir):
        wg = self._setup_wg(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        configs = list(wg.generate_configs())
        router_config = next(c for c in configs if c.me.config["name"] == "MyWireguardRouter")
        peer_names = [p.name for p in router_config.peers]
        assert "MyNotebook" in peer_names
        assert "MySecondNotebook" in peer_names
        assert "MyDesktop" in peer_names

    def test_p2mp_notebook_sees_only_router(self, tmp_dir):
        wg = self._setup_wg(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        configs = list(wg.generate_configs())
        notebook_config = next(c for c in configs if c.me.config["name"] == "MyNotebook")
        peer_names = [p.name for p in notebook_config.peers]
        assert "MyWireguardRouter" in peer_names
        # Notebooks should NOT connect to other notebooks/desktops
        assert "MySecondNotebook" not in peer_names
        assert "MyDesktop" not in peer_names

    def test_p2mp_desktop_sees_only_router(self, tmp_dir):
        wg = self._setup_wg(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        configs = list(wg.generate_configs())
        desktop_config = next(c for c in configs if c.me.config["name"] == "MyDesktop")
        peer_names = [p.name for p in desktop_config.peers]
        assert "MyWireguardRouter" in peer_names
        assert "MyNotebook" not in peer_names

    def test_s2s_each_server_sees_other(self, tmp_dir):
        wg = self._setup_wg(tmp_dir, SITE2SITE_CONFIG)
        configs = list(wg.generate_configs())
        for config in configs:
            # Each server should have exactly 1 peer (the other server)
            assert len(config.peers) == 1

    def test_disabled_peer_excluded(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "active", "addresses": ["10.0.0.1/24"], "type": "Server", "endpoint": "a:1"},
                {"name": "disabled", "addresses": ["10.0.0.2/24"], "type": "Server", "disabled": True},
            ],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        assert len(configs) == 1
        assert configs[0].me.config["name"] == "active"

    def test_unknown_type_skipped(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "known", "addresses": ["10.0.0.1/24"], "type": "Server", "endpoint": "a:1"},
                {"name": "unknown", "addresses": ["10.0.0.2/24"], "type": "UnknownType"},
            ],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        # The unknown type peer should be skipped when generating its own config
        names = [c.me.config["name"] for c in configs]
        assert "unknown" not in names
        assert "known" in names

    def test_allowed_ips_include_addresses(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "addresses": ["10.0.0.1/24"], "type": "Server", "endpoint": "a:1"},
                {"name": "s2", "addresses": ["10.0.0.2/24"], "type": "Server", "endpoint": "b:2"},
            ],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        s1_config = next(c for c in configs if c.me.config["name"] == "s1")
        s2_peer = s1_config.peers[0]
        assert "10.0.0.2/32" in s2_peer.allowed_ips

    def test_allowed_ips_include_provides_routes(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "addresses": ["10.0.0.1/24"], "type": "Server", "endpoint": "a:1"},
                {"name": "s2", "addresses": ["10.0.0.2/24"], "type": "Server",
                 "provides_routes": ["192.168.1.0/24"], "endpoint": "b:2"},
            ],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        s1_config = next(c for c in configs if c.me.config["name"] == "s1")
        s2_peer = s1_config.peers[0]
        assert "192.168.1.0/24" in s2_peer.allowed_ips
        assert "10.0.0.2/32" in s2_peer.allowed_ips

    def test_allowed_ips_sorted_and_deduped(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "addresses": ["10.0.0.1/24"], "type": "Server", "endpoint": "a:1"},
                {"name": "s2", "addresses": ["10.0.0.2/24"], "type": "Server",
                 "provides_routes": ["10.0.0.2/32"], "endpoint": "b:2"},
            ],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        s1_config = next(c for c in configs if c.me.config["name"] == "s1")
        aips = s1_config.peers[0].allowed_ips
        assert aips == sorted(set(aips))

    def test_ipv6_address_gets_slash_128(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "addresses": ["10.0.0.1/24"], "type": "Server", "endpoint": "a:1"},
                {"name": "s2", "addresses": ["fd00::2/64"], "type": "Server", "endpoint": "b:2"},
            ],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        s1_config = next(c for c in configs if c.me.config["name"] == "s1")
        s2_peer = s1_config.peers[0]
        assert "fd00::2/128" in s2_peer.allowed_ips

    def test_neither_reachable_excluded(self, tmp_dir):
        """Two peers without endpoints can't reach each other."""
        config = {
            "rules": {"Client": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "c1", "addresses": ["10.0.0.1/24"], "type": "Client"},
                {"name": "c2", "addresses": ["10.0.0.2/24"], "type": "Client"},
            ],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        for config_info in configs:
            assert len(config_info.peers) == 0

    def test_use_psk_flag(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "addresses": ["10.0.0.1/24"], "type": "Server",
                 "endpoint": "a:1", "use_psk": True},
                {"name": "s2", "addresses": ["10.0.0.2/24"], "type": "Server",
                 "endpoint": "b:2", "use_psk": False},
            ],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        s1_config = next(c for c in configs if c.me.config["name"] == "s1")
        assert s1_config.peers[0].use_psk is False  # s2's use_psk
        s2_config = next(c for c in configs if c.me.config["name"] == "s2")
        assert s2_config.peers[0].use_psk is True  # s1's use_psk

    def test_single_peer_no_self_connection(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "lonely", "addresses": ["10.0.0.1/24"], "type": "Server", "endpoint": "a:1"},
            ],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        assert len(configs) == 1
        assert len(configs[0].peers) == 0

    def test_empty_peers_list(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        assert len(configs) == 0

    def test_multiple_addresses_per_peer(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "addresses": ["10.0.0.1/24", "fd00::1/64"], "type": "Server", "endpoint": "a:1"},
                {"name": "s2", "addresses": ["10.0.0.2/24"], "type": "Server", "endpoint": "b:2"},
            ],
        }
        wg = self._setup_wg(tmp_dir, config)
        configs = list(wg.generate_configs())
        s2_config = next(c for c in configs if c.me.config["name"] == "s2")
        # s2 should have s1 as peer with both addresses in allowed_ips
        s1_peer = s2_config.peers[0]
        assert "10.0.0.1/32" in s1_peer.allowed_ips
        assert "fd00::1/128" in s1_peer.allowed_ips


# ===================================================================
# WireguardConfigurator config file generation (write to disk)
# ===================================================================
class TestConfigFileGeneration:
    """Test that generate_wg_config, generate_mikrotik_config, generate_openwrt_config
    actually write files to disk with correct content."""

    def _setup_and_generate(self, tmp_dir, config, config_name="test.json"):
        path = write_config(tmp_dir, config, config_name)
        wg = WireguardConfigurator(path)
        os.makedirs(wg.keys_dir, exist_ok=True)
        os.makedirs(wg.config_dir, exist_ok=True)
        os.makedirs(wg.mikrotik_dir, exist_ok=True)
        os.makedirs(wg.openwrt_dir, exist_ok=True)
        os.makedirs(wg.mobile_dir, exist_ok=True)
        keys = [
            (FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK),
            (FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2),
            (FAKE_PRIVKEY3, FAKE_PUBKEY3, FAKE_PSK3),
        ]
        for i, peer in enumerate(config["peers"]):
            if peer.get("disabled"):
                continue
            k = keys[i % len(keys)]
            create_fake_keys(wg.config_name, peer["name"], *k)
        return wg

    # --- Standard WireGuard config files ---
    def test_wg_config_files_created_p2mp(self, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        for ci in wg.generate_configs():
            wg.generate_wg_config(ci)
        for peer in POINT_TO_MULTIPOINT_CONFIG["peers"]:
            conf_file = os.path.join(wg.config_dir, f"{peer['name']}.conf")
            assert os.path.isfile(conf_file), f"Missing {conf_file}"

    def test_wg_config_files_created_s2s(self, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, SITE2SITE_CONFIG)
        for ci in wg.generate_configs():
            wg.generate_wg_config(ci)
        for peer in SITE2SITE_CONFIG["peers"]:
            conf_file = os.path.join(wg.config_dir, f"{peer['name']}.conf")
            assert os.path.isfile(conf_file)

    def test_wg_config_content_has_interface(self, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        for ci in wg.generate_configs():
            wg.generate_wg_config(ci)
        conf_file = os.path.join(wg.config_dir, "MyWireguardRouter.conf")
        with open(conf_file) as f:
            content = f.read()
        assert "[Interface]" in content

    def test_wg_config_content_has_peers(self, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        for ci in wg.generate_configs():
            wg.generate_wg_config(ci)
        conf_file = os.path.join(wg.config_dir, "MyWireguardRouter.conf")
        with open(conf_file) as f:
            content = f.read()
        assert "[Peer]" in content
        # Router should have 3 peers
        assert content.count("[Peer]") == 3

    def test_wg_config_listen_port(self, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        for ci in wg.generate_configs():
            wg.generate_wg_config(ci)
        # Router has endpoint with port
        with open(os.path.join(wg.config_dir, "MyWireguardRouter.conf")) as f:
            content = f.read()
        assert "ListenPort = 22781" in content
        # Notebook has no endpoint
        with open(os.path.join(wg.config_dir, "MyNotebook.conf")) as f:
            content = f.read()
        assert "ListenPort" not in content

    # --- MikroTik config files ---
    def test_mikrotik_config_files_created(self, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        for ci in wg.generate_configs():
            wg.generate_mikrotik_config(ci)
        for peer in POINT_TO_MULTIPOINT_CONFIG["peers"]:
            mik_file = os.path.join(wg.mikrotik_dir, f"{peer['name']}.mik")
            assert os.path.isfile(mik_file)

    def test_mikrotik_config_content(self, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        for ci in wg.generate_configs():
            wg.generate_mikrotik_config(ci)
        with open(os.path.join(wg.mikrotik_dir, "MyWireguardRouter.mik")) as f:
            content = f.read()
        assert "/interface wireguard add" in content
        assert "/interface wireguard peers add" in content

    def test_mikrotik_interface_name(self, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        for ci in wg.generate_configs():
            wg.generate_mikrotik_config(ci)
        with open(os.path.join(wg.mikrotik_dir, "MyWireguardRouter.mik")) as f:
            content = f.read()
        assert "name=WGPointToMultipoint" in content

    # --- OpenWRT config files ---
    def test_openwrt_config_files_created(self, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        for ci in wg.generate_configs():
            wg.generate_openwrt_config(ci)
        for peer in POINT_TO_MULTIPOINT_CONFIG["peers"]:
            cfg_file = os.path.join(wg.openwrt_dir, f"{peer['name']}.cfg")
            assert os.path.isfile(cfg_file)

    def test_openwrt_config_content(self, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        for ci in wg.generate_configs():
            wg.generate_openwrt_config(ci)
        with open(os.path.join(wg.openwrt_dir, "MyWireguardRouter.cfg")) as f:
            content = f.read()
        assert "config interface" in content
        assert "option proto 'wireguard'" in content

    # --- Mobile QR generation (mocked subprocess) ---
    @patch("subprocess.check_output")
    def test_mobile_qr_generates(self, mock_subproc, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        configs = list(wg.generate_configs())
        for ci in configs:
            wg.generate_wg_config(ci)  # QR depends on .conf existing
        for ci in configs:
            wg.generate_mobile_qr(ci)
        # Should have been called for each peer (2 calls each: png + svg)
        assert mock_subproc.call_count == len(configs) * 2

    @patch("subprocess.check_output", side_effect=FileNotFoundError("qrencode not found"))
    def test_mobile_qr_missing_qrencode(self, mock_subproc, tmp_dir):
        wg = self._setup_and_generate(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        configs = list(wg.generate_configs())
        for ci in configs:
            wg.generate_wg_config(ci)
        # Should not raise, just log error
        for ci in configs:
            wg.generate_mobile_qr(ci)


# ===================================================================
# Full pipeline tests (generate_configs → all outputs)
# ===================================================================
class TestFullPipeline:
    def _run_full(self, tmp_dir, config, config_name="test.json"):
        path = write_config(tmp_dir, config, config_name)
        wg = WireguardConfigurator(path)
        os.makedirs(wg.keys_dir, exist_ok=True)
        os.makedirs(wg.config_dir, exist_ok=True)
        os.makedirs(wg.mikrotik_dir, exist_ok=True)
        os.makedirs(wg.openwrt_dir, exist_ok=True)
        os.makedirs(wg.mobile_dir, exist_ok=True)
        keys = [
            (FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK),
            (FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2),
            (FAKE_PRIVKEY3, FAKE_PUBKEY3, FAKE_PSK3),
        ]
        for i, peer in enumerate(config["peers"]):
            if peer.get("disabled"):
                continue
            k = keys[i % len(keys)]
            create_fake_keys(wg.config_name, peer["name"], *k)
        configs = list(wg.generate_configs())
        for ci in configs:
            wg.generate_wg_config(ci)
            wg.generate_mikrotik_config(ci)
            wg.generate_openwrt_config(ci)
        return wg, configs

    @pytest.mark.parametrize("config,expected_count", [
        (POINT_TO_MULTIPOINT_CONFIG, 4),
        (SITE2SITE_CONFIG, 2),
    ])
    def test_full_pipeline(self, tmp_dir, config, expected_count):
        wg, configs = self._run_full(tmp_dir, config)
        assert len(configs) == expected_count

    def test_all_conf_files_exist(self, tmp_dir):
        wg, configs = self._run_full(tmp_dir, POINT_TO_MULTIPOINT_CONFIG)
        for ci in configs:
            name = ci.me.config["name"]
            assert os.path.isfile(os.path.join(wg.config_dir, f"{name}.conf"))
            assert os.path.isfile(os.path.join(wg.mikrotik_dir, f"{name}.mik"))
            assert os.path.isfile(os.path.join(wg.openwrt_dir, f"{name}.cfg"))

    def test_conf_file_not_empty(self, tmp_dir):
        wg, configs = self._run_full(tmp_dir, SITE2SITE_CONFIG)
        for ci in configs:
            name = ci.me.config["name"]
            for ext, d in [(".conf", wg.config_dir), (".mik", wg.mikrotik_dir), (".cfg", wg.openwrt_dir)]:
                path = os.path.join(d, f"{name}{ext}")
                assert os.path.getsize(path) > 0

    def test_three_peer_types_config(self, tmp_dir):
        config = {
            "rules": {
                "Router": {"connect_to": ["*"], "keepalive": 30},
                "Mobile": {"connect_to": ["Router"], "keepalive": 120},
                "Desktop": {"connect_to": ["Router"], "keepalive": 60},
            },
            "peers": [
                {"name": "router", "addresses": ["10.0.0.1/24"], "type": "Router", "endpoint": "r:1"},
                {"name": "phone", "addresses": ["10.0.0.2/24"], "type": "Mobile"},
                {"name": "pc", "addresses": ["10.0.0.3/24"], "type": "Desktop"},
            ],
        }
        wg, configs = self._run_full(tmp_dir, config)
        assert len(configs) == 3
        # Router has 2 peers
        router = next(c for c in configs if c.me.config["name"] == "router")
        assert len(router.peers) == 2
        # Mobile has 1 peer (router)
        phone = next(c for c in configs if c.me.config["name"] == "phone")
        assert len(phone.peers) == 1
        assert phone.peers[0].name == "router"

    def test_no_provides_routes_still_works(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "s1", "addresses": ["10.0.0.1/24"], "type": "Server", "endpoint": "a:1"},
                {"name": "s2", "addresses": ["10.0.0.2/24"], "type": "Server", "endpoint": "b:2"},
            ],
        }
        wg, configs = self._run_full(tmp_dir, config)
        assert len(configs) == 2
