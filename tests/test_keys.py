"""Tests for key management: load_keys, generate_and_save_keys,
generate_or_load_peer_keys, and the KeySet NamedTuple."""
import os
from unittest.mock import patch

import pytest

from guardmywire import (
    KeySet,
    key_filenames,
    load_keys,
    generate_and_save_keys,
    generate_or_load_peer_keys,
    generate_wireguard_keys,
    generate_wireguard_psk,
)
from tests.conftest import (
    FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK,
    FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2,
    create_fake_keys,
)


# ===================================================================
# KeySet NamedTuple
# ===================================================================
class TestKeySet:
    def test_creation(self):
        ks = KeySet("priv", "pub", "psk")
        assert ks.private_key == "priv"
        assert ks.public_key == "pub"
        assert ks.psk == "psk"

    def test_tuple_unpacking(self):
        priv, pub, psk = KeySet("a", "b", "c")
        assert priv == "a"
        assert pub == "b"
        assert psk == "c"

    def test_indexing(self):
        ks = KeySet("a", "b", "c")
        assert ks[0] == "a"
        assert ks[1] == "b"
        assert ks[2] == "c"

    def test_equality(self):
        assert KeySet("a", "b", "c") == KeySet("a", "b", "c")
        assert KeySet("a", "b", "c") != KeySet("x", "b", "c")

    def test_immutable(self):
        ks = KeySet("a", "b", "c")
        with pytest.raises(AttributeError):
            ks.private_key = "new"

    @pytest.mark.parametrize("priv,pub,psk", [
        ("", "", ""),
        ("a" * 100, "b" * 100, "c" * 100),
        ("key with spaces", "pub with spaces", "psk with spaces"),
    ])
    def test_various_values(self, priv, pub, psk):
        ks = KeySet(priv, pub, psk)
        assert ks.private_key == priv
        assert ks.public_key == pub
        assert ks.psk == psk

    def test_repr(self):
        ks = KeySet("priv", "pub", "psk")
        r = repr(ks)
        assert "KeySet" in r
        assert "priv" in r

    def test_len(self):
        ks = KeySet("a", "b", "c")
        assert len(ks) == 3

    def test_hash(self):
        ks1 = KeySet("a", "b", "c")
        ks2 = KeySet("a", "b", "c")
        assert hash(ks1) == hash(ks2)
        s = {ks1, ks2}
        assert len(s) == 1


# ===================================================================
# load_keys
# ===================================================================
class TestLoadKeys:
    def test_load_keys_success(self, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        create_fake_keys(cfg_name, "peer1")
        ks = load_keys(cfg_name, "peer1")
        assert ks.private_key == FAKE_PRIVKEY
        assert ks.public_key == FAKE_PUBKEY
        assert ks.psk == FAKE_PSK

    def test_load_keys_strips_whitespace(self, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        keys_dir = os.path.join(cfg_name, "keys")
        os.makedirs(keys_dir, exist_ok=True)
        for f, c in [("p.privkey", "  priv  \n"), ("p.pubkey", " pub \n"), ("p.psk", " psk \n")]:
            with open(os.path.join(keys_dir, f), "w") as fh:
                fh.write(c)
        ks = load_keys(cfg_name, "p")
        assert ks.private_key == "priv"
        assert ks.public_key == "pub"
        assert ks.psk == "psk"

    def test_load_keys_file_not_found(self, tmp_dir):
        with pytest.raises(FileNotFoundError):
            load_keys(os.path.join(tmp_dir, "nonexistent"), "peer")

    @pytest.mark.parametrize("missing", ["privkey", "pubkey", "psk"])
    def test_load_keys_missing_one_file(self, tmp_dir, missing):
        cfg_name = os.path.join(tmp_dir, "cfg")
        create_fake_keys(cfg_name, "peer1")
        # Remove one file
        ext_map = {"privkey": ".privkey", "pubkey": ".pubkey", "psk": ".psk"}
        os.remove(os.path.join(cfg_name, "keys", f"peer1{ext_map[missing]}"))
        with pytest.raises(FileNotFoundError):
            load_keys(cfg_name, "peer1")

    @pytest.mark.parametrize("peer_name", [
        "simple",
        "with.dots",
        "with-dashes",
        "with_underscores",
        "CamelCase",
    ])
    def test_load_various_peer_names(self, tmp_dir, peer_name):
        cfg_name = os.path.join(tmp_dir, "cfg")
        create_fake_keys(cfg_name, peer_name)
        ks = load_keys(cfg_name, peer_name)
        assert ks.private_key == FAKE_PRIVKEY

    def test_load_keys_empty_files(self, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        keys_dir = os.path.join(cfg_name, "keys")
        os.makedirs(keys_dir, exist_ok=True)
        for f in ["p.privkey", "p.pubkey", "p.psk"]:
            with open(os.path.join(keys_dir, f), "w") as fh:
                fh.write("")
        ks = load_keys(cfg_name, "p")
        assert ks.private_key == ""
        assert ks.public_key == ""
        assert ks.psk == ""


# ===================================================================
# generate_and_save_keys (mocked subprocess)
# ===================================================================
class TestGenerateAndSaveKeys:
    @patch("guardmywire.generate_wireguard_psk", return_value=FAKE_PSK)
    @patch("guardmywire.generate_wireguard_keys", return_value=(FAKE_PRIVKEY, FAKE_PUBKEY))
    def test_creates_key_files(self, mock_keys, mock_psk, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        os.makedirs(os.path.join(cfg_name, "keys"), exist_ok=True)
        generate_and_save_keys(cfg_name, "peer1")
        priv_f, pub_f, psk_f = key_filenames(cfg_name, "peer1")
        assert os.path.isfile(priv_f)
        assert os.path.isfile(pub_f)
        assert os.path.isfile(psk_f)

    @patch("guardmywire.generate_wireguard_psk", return_value=FAKE_PSK)
    @patch("guardmywire.generate_wireguard_keys", return_value=(FAKE_PRIVKEY, FAKE_PUBKEY))
    def test_file_contents(self, mock_keys, mock_psk, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        os.makedirs(os.path.join(cfg_name, "keys"), exist_ok=True)
        generate_and_save_keys(cfg_name, "peer1")
        ks = load_keys(cfg_name, "peer1")
        assert ks.private_key == FAKE_PRIVKEY
        assert ks.public_key == FAKE_PUBKEY
        assert ks.psk == FAKE_PSK

    @patch("guardmywire.generate_wireguard_psk", return_value=FAKE_PSK)
    @patch("guardmywire.generate_wireguard_keys", return_value=(FAKE_PRIVKEY, FAKE_PUBKEY))
    def test_overwrites_existing(self, mock_keys, mock_psk, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        os.makedirs(os.path.join(cfg_name, "keys"), exist_ok=True)
        create_fake_keys(cfg_name, "peer1", "old_priv", "old_pub", "old_psk")
        generate_and_save_keys(cfg_name, "peer1")
        ks = load_keys(cfg_name, "peer1")
        assert ks.private_key == FAKE_PRIVKEY


# ===================================================================
# generate_wireguard_keys / generate_wireguard_psk (mocked)
# ===================================================================
class TestGenerateWireguardKeys:
    @patch("subprocess.check_output")
    def test_generate_keys(self, mock_subproc):
        mock_subproc.side_effect = [
            b"PrivateKeyData==\n",
            b"PublicKeyData==\n",
        ]
        priv, pub = generate_wireguard_keys()
        assert priv == "PrivateKeyData=="
        assert pub == "PublicKeyData=="

    @patch("subprocess.check_output")
    def test_generate_psk(self, mock_subproc):
        mock_subproc.return_value = b"PresharedKeyData==\n"
        psk = generate_wireguard_psk()
        assert psk == "PresharedKeyData=="

    @patch("subprocess.check_output", side_effect=FileNotFoundError("wg not found"))
    def test_generate_keys_wg_not_found(self, mock_subproc):
        with pytest.raises(FileNotFoundError):
            generate_wireguard_keys()

    @patch("subprocess.check_output", side_effect=FileNotFoundError("wg not found"))
    def test_generate_psk_wg_not_found(self, mock_subproc):
        with pytest.raises(FileNotFoundError):
            generate_wireguard_psk()

    @patch("subprocess.check_output")
    def test_keys_stripped(self, mock_subproc):
        mock_subproc.side_effect = [
            b"  PrivKey  \n\n",
            b"  PubKey  \n\n",
        ]
        priv, pub = generate_wireguard_keys()
        assert priv == "PrivKey"
        assert pub == "PubKey"

    @patch("subprocess.check_output")
    def test_psk_stripped(self, mock_subproc):
        mock_subproc.return_value = b"  PSK  \n\n"
        psk = generate_wireguard_psk()
        assert psk == "PSK"


# ===================================================================
# generate_or_load_peer_keys (mocked)
# ===================================================================
class TestGenerateOrLoadPeerKeys:
    @patch("guardmywire.generate_and_save_keys")
    def test_loads_existing_keys(self, mock_gen, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        create_fake_keys(cfg_name, "peer1")
        peers = [{"name": "peer1"}]
        result = generate_or_load_peer_keys(cfg_name, peers)
        assert "peer1" in result
        assert result["peer1"].private_key == FAKE_PRIVKEY
        mock_gen.assert_not_called()

    @patch("guardmywire.generate_and_save_keys")
    def test_generates_when_no_keys(self, mock_gen, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        os.makedirs(os.path.join(cfg_name, "keys"), exist_ok=True)
        # generate_and_save_keys will be called but won't actually create files,
        # then load_keys will fail. We need to make it actually create the files.
        def side_effect(cn, pn):
            create_fake_keys(cn, pn)
        mock_gen.side_effect = side_effect
        peers = [{"name": "peer1"}]
        result = generate_or_load_peer_keys(cfg_name, peers)
        assert "peer1" in result
        mock_gen.assert_called_once_with(cfg_name, "peer1")

    @patch("guardmywire.generate_and_save_keys")
    def test_skips_disabled_peers(self, mock_gen, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        peers = [{"name": "peer1", "disabled": True}]
        result = generate_or_load_peer_keys(cfg_name, peers)
        assert "peer1" not in result
        mock_gen.assert_not_called()

    @patch("guardmywire.generate_and_save_keys")
    def test_multiple_peers(self, mock_gen, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        create_fake_keys(cfg_name, "peer1", FAKE_PRIVKEY, FAKE_PUBKEY, FAKE_PSK)
        create_fake_keys(cfg_name, "peer2", FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2)
        peers = [{"name": "peer1"}, {"name": "peer2"}]
        result = generate_or_load_peer_keys(cfg_name, peers)
        assert result["peer1"].private_key == FAKE_PRIVKEY
        assert result["peer2"].private_key == FAKE_PRIVKEY2

    @patch("guardmywire.generate_and_save_keys")
    def test_mixed_existing_and_new(self, mock_gen, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        create_fake_keys(cfg_name, "existing")
        def side_effect(cn, pn):
            create_fake_keys(cn, pn, FAKE_PRIVKEY2, FAKE_PUBKEY2, FAKE_PSK2)
        mock_gen.side_effect = side_effect
        peers = [{"name": "existing"}, {"name": "new"}]
        result = generate_or_load_peer_keys(cfg_name, peers)
        assert result["existing"].private_key == FAKE_PRIVKEY
        assert result["new"].private_key == FAKE_PRIVKEY2

    @patch("guardmywire.generate_and_save_keys")
    def test_disabled_false_not_skipped(self, mock_gen, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        create_fake_keys(cfg_name, "peer1")
        peers = [{"name": "peer1", "disabled": False}]
        result = generate_or_load_peer_keys(cfg_name, peers)
        assert "peer1" in result

    @patch("guardmywire.generate_and_save_keys")
    def test_empty_peers_list(self, mock_gen, tmp_dir):
        cfg_name = os.path.join(tmp_dir, "cfg")
        result = generate_or_load_peer_keys(cfg_name, [])
        assert result == {}
        mock_gen.assert_not_called()
