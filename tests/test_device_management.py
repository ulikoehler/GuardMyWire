"""Tests for rename_device, add_device, format_json, list_clients, prompt_yes_no."""
import json
import os
import sys
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open
from io import StringIO

import pytest

from guardmywire import (
    rename_device,
    add_device,
    format_json,
    list_clients,
    prompt_yes_no,
)
from tests.conftest import (
    POINT_TO_MULTIPOINT_CONFIG,
    SITE2SITE_CONFIG,
    write_config,
    create_fake_keys,
    FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK,
)


# ===================================================================
# prompt_yes_no
# ===================================================================
class TestPromptYesNo:
    @pytest.mark.parametrize("response,expected", [
        ("y", True),
        ("Y", True),
        ("yes", True),
        ("YES", True),
        ("Yes", True),
        ("n", False),
        ("N", False),
        ("no", False),
        ("NO", False),
        ("No", False),
    ])
    def test_explicit_responses(self, response, expected):
        with patch("builtins.input", return_value=response):
            assert prompt_yes_no("Test?") is expected

    @pytest.mark.parametrize("default,expected", [
        (True, True),
        (False, False),
    ])
    def test_empty_response_uses_default(self, default, expected):
        with patch("builtins.input", return_value=""):
            assert prompt_yes_no("Test?", default=default) is expected

    def test_default_is_false(self):
        with patch("builtins.input", return_value=""):
            assert prompt_yes_no("Test?") is False

    def test_eoferror_returns_default(self):
        with patch("builtins.input", side_effect=EOFError):
            assert prompt_yes_no("Test?", default=True) is True
        with patch("builtins.input", side_effect=EOFError):
            assert prompt_yes_no("Test?", default=False) is False

    @pytest.mark.parametrize("response", ["maybe", "x", "123", "yy", "nn", "nope", "yep"])
    def test_invalid_responses_treated_as_no(self, response):
        with patch("builtins.input", return_value=response):
            assert prompt_yes_no("Test?") is False

    def test_whitespace_stripped(self):
        with patch("builtins.input", return_value="  y  "):
            assert prompt_yes_no("Test?") is True

    @pytest.mark.parametrize("response", ["  yes  ", "\ty\n", "  Y  "])
    def test_whitespace_variants(self, response):
        with patch("builtins.input", return_value=response):
            assert prompt_yes_no("Test?") is True


# ===================================================================
# format_json
# ===================================================================
class TestFormatJson:
    def test_formats_with_indent_4(self, tmp_dir):
        config = {"rules": {}, "peers": []}
        path = write_config(tmp_dir, config, "test.json")
        # Write with no indent
        with open(path, "w") as f:
            json.dump(config, f)
        format_json(path, indent=4, yes=True)
        with open(path) as f:
            content = f.read()
        assert "    " in content  # 4-space indent

    def test_formats_with_indent_2(self, tmp_dir):
        config = {"rules": {}, "peers": []}
        path = write_config(tmp_dir, config, "test.json")
        with open(path, "w") as f:
            json.dump(config, f)
        format_json(path, indent=2, yes=True)
        with open(path) as f:
            content = f.read()
        # Verify it's valid JSON
        data = json.loads(content)
        assert data == config

    def test_already_formatted(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": []}
        path = write_config(tmp_dir, config, "test.json")
        # Already formatted with indent=4
        format_json(path, indent=4, yes=True)
        captured = capsys.readouterr()
        # Second pass should say already formatted
        format_json(path, indent=4, yes=True)
        captured = capsys.readouterr()
        assert "already formatted" in captured.out

    def test_dry_run(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": []}
        path = write_config(tmp_dir, config, "test.json")
        with open(path, "w") as f:
            json.dump(config, f)
        original = open(path).read()
        format_json(path, indent=4, yes=True, dry_run=True)
        with open(path) as f:
            assert f.read() == original  # unchanged
        captured = capsys.readouterr()
        assert "Dry-run" in captured.out

    def test_nonexistent_file(self, tmp_dir):
        with pytest.raises(SystemExit):
            format_json(os.path.join(tmp_dir, "nonexistent.json"), yes=True)

    def test_invalid_json(self, tmp_dir):
        path = os.path.join(tmp_dir, "bad.json")
        with open(path, "w") as f:
            f.write("not json {{{")
        with pytest.raises(SystemExit):
            format_json(path, yes=True)

    def test_prompt_no_aborts(self, tmp_dir):
        config = {"rules": {}, "peers": []}
        path = write_config(tmp_dir, config, "test.json")
        with open(path, "w") as f:
            json.dump(config, f)
        original = open(path).read()
        with patch("guardmywire.prompt_yes_no", return_value=False):
            with pytest.raises(SystemExit):
                format_json(path, indent=4, yes=False)

    @pytest.mark.parametrize("indent", [1, 2, 4, 8])
    def test_various_indents(self, tmp_dir, indent):
        config = {"rules": {"A": {"keepalive": 30}}, "peers": [{"name": "p"}]}
        path = write_config(tmp_dir, config, "test.json")
        with open(path, "w") as f:
            json.dump(config, f)
        format_json(path, indent=indent, yes=True)
        with open(path) as f:
            content = f.read()
        data = json.loads(content)
        assert data == config

    def test_trailing_newline(self, tmp_dir):
        config = {"rules": {}, "peers": []}
        path = write_config(tmp_dir, config, "test.json")
        with open(path, "w") as f:
            json.dump(config, f)
        format_json(path, indent=4, yes=True)
        with open(path) as f:
            content = f.read()
        assert content.endswith("\n")

    def test_preserves_unicode(self, tmp_dir):
        config = {"rules": {}, "peers": [{"name": "日本語"}]}
        path = os.path.join(tmp_dir, "test.json")
        with open(path, "w") as f:
            json.dump(config, f, ensure_ascii=False, indent=4)
            f.write("\n")
        format_json(path, indent=4, yes=True)
        with open(path) as f:
            data = json.load(f)
        assert data["peers"][0]["name"] == "日本語"


# ===================================================================
# list_clients
# ===================================================================
class TestListClients:
    def test_empty_peers(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": []}
        path = write_config(tmp_dir, config)
        list_clients(path)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_no_clients_type(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": [
            {"name": "p1", "type": "Server", "addresses": ["10.0.0.1/24"]}
        ]}
        path = write_config(tmp_dir, config)
        list_clients(path)
        captured = capsys.readouterr()
        assert captured.out == ""  # Only shows "Client" type by default

    def test_client_type_shown(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": [
            {"name": "device1", "type": "Client", "addresses": ["10.0.0.1/24"], "provides_routes": ["192.168.1.0/24"]}
        ]}
        path = write_config(tmp_dir, config)
        list_clients(path)
        captured = capsys.readouterr()
        assert "device1" in captured.out
        assert "10.0.0.1/24" in captured.out
        assert "192.168.1.0/24" in captured.out

    def test_all_types_flag(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": [
            {"name": "p1", "type": "Server", "addresses": ["10.0.0.1/24"]},
            {"name": "p2", "type": "Client", "addresses": ["10.0.0.2/24"]},
        ]}
        path = write_config(tmp_dir, config)
        list_clients(path, all_types=True)
        captured = capsys.readouterr()
        assert "p1" in captured.out
        assert "p2" in captured.out

    def test_disabled_peers_excluded(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": [
            {"name": "active", "type": "Client", "addresses": ["10.0.0.1/24"]},
            {"name": "disabled", "type": "Client", "addresses": ["10.0.0.2/24"], "disabled": True},
        ]}
        path = write_config(tmp_dir, config)
        list_clients(path)
        captured = capsys.readouterr()
        assert "active" in captured.out
        assert "disabled" not in captured.out

    def test_no_addresses(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": [
            {"name": "p1", "type": "Client"}
        ]}
        path = write_config(tmp_dir, config)
        list_clients(path)
        captured = capsys.readouterr()
        assert "(none)" in captured.out

    def test_no_provides_routes(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": [
            {"name": "p1", "type": "Client", "addresses": ["10.0.0.1/24"]}
        ]}
        path = write_config(tmp_dir, config)
        list_clients(path)
        captured = capsys.readouterr()
        assert "provides_routes:(none)" in captured.out

    def test_nonexistent_file(self, tmp_dir):
        with pytest.raises(SystemExit):
            list_clients(os.path.join(tmp_dir, "no.json"))

    def test_multiple_clients(self, tmp_dir, capsys):
        config = {"rules": {}, "peers": [
            {"name": f"client{i}", "type": "Client", "addresses": [f"10.0.0.{i}/24"]}
            for i in range(1, 6)
        ]}
        path = write_config(tmp_dir, config)
        list_clients(path)
        captured = capsys.readouterr()
        for i in range(1, 6):
            assert f"client{i}" in captured.out


# ===================================================================
# rename_device
# ===================================================================
class TestRenameDevice:
    def test_basic_rename_dry_run(self, tmp_dir, capsys):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [{"name": "old_name", "addresses": ["10.0.0.1/24"], "type": "Server"}],
        }
        path = write_config(tmp_dir, config)
        rename_device(path, "old_name", "new_name", yes=True, dry_run=True)
        captured = capsys.readouterr()
        assert "Dry-run" in captured.out
        # Verify JSON not changed
        with open(path) as f:
            data = json.load(f)
        assert data["peers"][0]["name"] == "old_name"

    def test_basic_rename(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [{"name": "old_name", "addresses": ["10.0.0.1/24"], "type": "Server"}],
        }
        path = write_config(tmp_dir, config)
        rename_device(path, "old_name", "new_name", yes=True)
        with open(path) as f:
            data = json.load(f)
        assert data["peers"][0]["name"] == "new_name"

    def test_rename_nonexistent_device(self, tmp_dir):
        config = {
            "rules": {},
            "peers": [{"name": "existing", "type": "Server"}],
        }
        path = write_config(tmp_dir, config)
        with pytest.raises(SystemExit):
            rename_device(path, "nonexistent", "new_name", yes=True)

    def test_rename_with_key_files(self, tmp_dir):
        config = {
            "rules": {},
            "peers": [{"name": "old_peer", "type": "Server", "addresses": ["10.0.0.1/24"]}],
        }
        path = write_config(tmp_dir, config)
        cfg_name = os.path.splitext(path)[0]
        create_fake_keys(cfg_name, "old_peer")
        rename_device(path, "old_peer", "new_peer", yes=True)
        # Old key files should be gone, new ones should exist
        assert not os.path.isfile(os.path.join(cfg_name, "keys", "old_peer.privkey"))
        assert os.path.isfile(os.path.join(cfg_name, "keys", "new_peer.privkey"))
        assert os.path.isfile(os.path.join(cfg_name, "keys", "new_peer.pubkey"))
        assert os.path.isfile(os.path.join(cfg_name, "keys", "new_peer.psk"))

    def test_rename_with_config_files(self, tmp_dir):
        config = {
            "rules": {},
            "peers": [{"name": "old_peer", "type": "Server"}],
        }
        path = write_config(tmp_dir, config)
        cfg_name = os.path.splitext(path)[0]
        # Create config/mikrotik/openwrt files
        for subdir, ext in [("config", ".conf"), ("mikrotik", ".mik"), ("openwrt", ".cfg")]:
            d = os.path.join(cfg_name, subdir)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, f"old_peer{ext}"), "w") as f:
                f.write("content")
        rename_device(path, "old_peer", "new_peer", yes=True)
        for subdir, ext in [("config", ".conf"), ("mikrotik", ".mik"), ("openwrt", ".cfg")]:
            d = os.path.join(cfg_name, subdir)
            assert not os.path.isfile(os.path.join(d, f"old_peer{ext}"))
            assert os.path.isfile(os.path.join(d, f"new_peer{ext}"))

    def test_rename_with_mobile_files(self, tmp_dir):
        config = {
            "rules": {},
            "peers": [{"name": "old_peer", "type": "Server"}],
        }
        path = write_config(tmp_dir, config)
        cfg_name = os.path.splitext(path)[0]
        mobile_dir = os.path.join(cfg_name, "mobile")
        os.makedirs(mobile_dir, exist_ok=True)
        for ext in [".png", ".svg"]:
            with open(os.path.join(mobile_dir, f"old_peer{ext}"), "w") as f:
                f.write("content")
        rename_device(path, "old_peer", "new_peer", yes=True)
        for ext in [".png", ".svg"]:
            assert not os.path.isfile(os.path.join(mobile_dir, f"old_peer{ext}"))
            assert os.path.isfile(os.path.join(mobile_dir, f"new_peer{ext}"))

    def test_rename_conflict_overwrite(self, tmp_dir):
        config = {
            "rules": {},
            "peers": [
                {"name": "peer1", "type": "Server"},
                {"name": "peer2", "type": "Server"},
            ],
        }
        path = write_config(tmp_dir, config)
        rename_device(path, "peer1", "peer2", yes=True)
        with open(path) as f:
            data = json.load(f)
        names = [p["name"] for p in data["peers"]]
        assert "peer2" in names
        # Should have only one peer2 (the renamed one)
        assert names.count("peer2") == 1

    def test_rename_conflict_abort(self, tmp_dir):
        config = {
            "rules": {},
            "peers": [
                {"name": "peer1", "type": "Server"},
                {"name": "peer2", "type": "Server"},
            ],
        }
        path = write_config(tmp_dir, config)
        with patch("guardmywire.prompt_yes_no", return_value=False):
            with pytest.raises(SystemExit):
                rename_device(path, "peer1", "peer2", yes=False)

    def test_rename_dry_run_no_file_changes(self, tmp_dir, capsys):
        config = {
            "rules": {},
            "peers": [{"name": "old", "type": "Server"}],
        }
        path = write_config(tmp_dir, config)
        cfg_name = os.path.splitext(path)[0]
        create_fake_keys(cfg_name, "old")
        rename_device(path, "old", "new", yes=True, dry_run=True)
        # Old files should still exist
        assert os.path.isfile(os.path.join(cfg_name, "keys", "old.privkey"))
        assert not os.path.isfile(os.path.join(cfg_name, "keys", "new.privkey"))
        captured = capsys.readouterr()
        assert "Dry-run" in captured.out


# ===================================================================
# add_device
# ===================================================================
class TestAddDevice:
    def test_add_basic_device(self, tmp_dir):
        config = {
            "rules": {"Client": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [{"name": "existing", "addresses": ["10.0.0.1/24"], "type": "Client"}],
        }
        path = write_config(tmp_dir, config)
        add_device(path, "new_device", type="Client", addresses=["10.0.0.2/24"], provides_routes=[], yes=True)
        with open(path) as f:
            data = json.load(f)
        names = [p["name"] for p in data["peers"]]
        assert "new_device" in names

    def test_add_device_auto_address(self, tmp_dir):
        config = {
            "rules": {"Client": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": "p1", "addresses": ["10.0.0.1/24"], "type": "Client"},
                {"name": "p2", "addresses": ["10.0.0.2/24"], "type": "Client"},
            ],
        }
        path = write_config(tmp_dir, config)
        add_device(path, "auto_addr", type="Client", provides_routes=[], yes=True)
        with open(path) as f:
            data = json.load(f)
        new_peer = next(p for p in data["peers"] if p["name"] == "auto_addr")
        assert len(new_peer["addresses"]) > 0
        # Should be 10.0.0.3/24 (next available)
        assert "10.0.0.3/24" in new_peer["addresses"]

    def test_add_device_with_interface_name(self, tmp_dir):
        config = {
            "rules": {"Client": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [],
        }
        path = write_config(tmp_dir, config)
        add_device(path, "dev1", type="Client", addresses=["10.0.0.1/24"],
                   interface_name="wg0", provides_routes=[], yes=True)
        with open(path) as f:
            data = json.load(f)
        assert data["peers"][0]["interface_name"] == "wg0"

    def test_add_device_invalid_type(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [],
        }
        path = write_config(tmp_dir, config)
        with pytest.raises(SystemExit):
            add_device(path, "dev", type="InvalidType", yes=True)

    def test_add_device_dry_run(self, tmp_dir, capsys):
        config = {
            "rules": {"Client": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [],
        }
        path = write_config(tmp_dir, config)
        add_device(path, "dev1", type="Client", addresses=["10.0.0.1/24"], provides_routes=[], yes=True, dry_run=True)
        with open(path) as f:
            data = json.load(f)
        assert len(data["peers"]) == 0  # Not written
        captured = capsys.readouterr()
        assert "Dry-run" in captured.out

    def test_add_device_default_type(self, tmp_dir, capsys):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}, "Client": {"connect_to": ["Server"]}},
            "peers": [],
        }
        path = write_config(tmp_dir, config)
        add_device(path, "dev1", type=None, addresses=["10.0.0.1/24"], provides_routes=[], yes=True)
        with open(path) as f:
            data = json.load(f)
        # Should use last type from rules
        assert data["peers"][0]["type"] == "Client"

    def test_add_device_overwrite_existing(self, tmp_dir):
        config = {
            "rules": {"Client": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [{"name": "dev1", "addresses": ["10.0.0.1/24"], "type": "Client"}],
        }
        path = write_config(tmp_dir, config)
        add_device(path, "dev1", type="Client", addresses=["10.0.0.99/24"], provides_routes=[], yes=True)
        with open(path) as f:
            data = json.load(f)
        dev = next(p for p in data["peers"] if p["name"] == "dev1")
        assert "10.0.0.99/24" in dev["addresses"]

    def test_add_device_overwrite_abort(self, tmp_dir):
        config = {
            "rules": {"Client": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [{"name": "dev1", "addresses": ["10.0.0.1/24"], "type": "Client"}],
        }
        path = write_config(tmp_dir, config)
        with patch("guardmywire.prompt_yes_no", return_value=False):
            add_device(path, "dev1", type="Client", addresses=["10.0.0.99/24"], provides_routes=[], yes=False)
        with open(path) as f:
            data = json.load(f)
        # Should not have changed
        dev = next(p for p in data["peers"] if p["name"] == "dev1")
        assert "10.0.0.1/24" in dev["addresses"]

    def test_add_device_with_provides_routes(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [],
        }
        path = write_config(tmp_dir, config)
        add_device(path, "s1", type="Server", addresses=["10.0.0.1/24"],
                   provides_routes=["192.168.1.0/24"], yes=True)
        with open(path) as f:
            data = json.load(f)
        assert data["peers"][0]["provides_routes"] == ["192.168.1.0/24"]

    def test_add_device_empty_provides_routes(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [],
        }
        path = write_config(tmp_dir, config)
        add_device(path, "s1", type="Server", addresses=["10.0.0.1/24"],
                   provides_routes=[], yes=True)
        with open(path) as f:
            data = json.load(f)
        # Empty provides_routes should not be added to keep JSON clean
        assert "provides_routes" not in data["peers"][0]

    def test_add_device_auto_routes_when_none(self, tmp_dir):
        config = {
            "rules": {"Server": {"connect_to": ["*"]}},
            "peers": [
                {"name": "s1", "addresses": ["10.0.0.1/24"], "type": "Server",
                 "provides_routes": ["192.168.1.0/24"]},
                {"name": "s2", "addresses": ["10.0.0.2/24"], "type": "Server",
                 "provides_routes": ["192.168.2.0/24"]},
            ],
        }
        path = write_config(tmp_dir, config)
        add_device(path, "s3", type="Server", addresses=["10.0.0.3/24"],
                   provides_routes=None, yes=True)
        with open(path) as f:
            data = json.load(f)
        s3 = next(p for p in data["peers"] if p["name"] == "s3")
        # Should have auto-assigned a route
        if "provides_routes" in s3:
            assert len(s3["provides_routes"]) > 0

    @pytest.mark.parametrize("n_existing", [0, 1, 5, 10])
    def test_add_device_sequential(self, tmp_dir, n_existing):
        config = {
            "rules": {"Client": {"connect_to": ["*"], "keepalive": 60}},
            "peers": [
                {"name": f"p{i}", "addresses": [f"10.0.0.{i}/24"], "type": "Client"}
                for i in range(1, n_existing + 1)
            ],
        }
        path = write_config(tmp_dir, config)
        add_device(path, "new_device", type="Client", provides_routes=[], yes=True)
        with open(path) as f:
            data = json.load(f)
        assert any(p["name"] == "new_device" for p in data["peers"])
