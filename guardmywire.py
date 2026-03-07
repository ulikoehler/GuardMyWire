#!/usr/bin/env python3
import subprocess
import os.path
import os
import shutil
import sys
import ipaddress
import json
import argparse
from typing import NamedTuple, List
import structlog
from collections import Counter

logger = structlog.get_logger()

def generate_wireguard_keys():
    """
    Generate a WireGuard private & public key
    Requires that the 'wg' command is available on PATH
    Returns (private_key, public_key), both strings
    """
    privkey = subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    pubkey = subprocess.check_output(f"echo '{privkey}' | wg pubkey", shell=True).decode("utf-8").strip()
    return (privkey, pubkey)

def generate_wireguard_psk():
    """
    Generate a WireGuard private & public key
    Requires that the 'wg' command is available on PATH
    Returns 
    """
    return subprocess.check_output("wg genpsk", shell=True).decode("utf-8").strip()

def key_filenames(config_name, peer_name):
    privkey_file = os.path.join(config_name, "keys", f"{peer_name}.privkey")
    pubkey_file = os.path.join(config_name, "keys", f"{peer_name}.pubkey")
    psk_file = os.path.join(config_name, "keys", f"{peer_name}.psk")
    return privkey_file, pubkey_file, psk_file
    
def load_keys(config_name, peer_name):
    # Gen filenames
    privkey_file, pubkey_file, psk_file = key_filenames(config_name, peer_name)
    # read files
    with open(privkey_file) as infile:
        privkey = infile.read().strip()
    with open(pubkey_file) as infile:
        pubkey = infile.read().strip()
    with open(psk_file) as infile:
        psk = infile.read().strip()
    # return
    return KeySet(privkey, pubkey, psk)

def generate_and_save_keys(config_name, peer_name):
    # Gen filenames
    privkey_file, pubkey_file, psk_file = key_filenames(config_name, peer_name)
    # Generate keys
    privkey, pubkey = generate_wireguard_keys()
    psk = generate_wireguard_psk()
    # Save keys to file
    with open(privkey_file, "w") as outfile:
        outfile.write(privkey)
    with open(pubkey_file, "w") as outfile:
        outfile.write(pubkey)
    with open(psk_file, "w") as outfile:
        outfile.write(psk)

def generate_interface_config(name, private_key, address, listen_port=None):
    cfg = f"""[Interface]
# Name = {name}
PrivateKey = {private_key}
Address = {address}\n"""
    if listen_port is not None:
        cfg += f"ListenPort = {listen_port}\n"
    return cfg

def generate_mikrotik_interface_config(name, private_key, addresses, interface_name, listen_port=None):
    if interface_name is None:
        interface_name = name
    # Add command for adding wireguard interface
    cfg = f"/interface wireguard add mtu=1420 name={interface_name} comment={name} private-key=\"{private_key}\""
    if listen_port is not None:
        cfg += f" listen-port={listen_port}"

    cfg += "\n"

    # Add commands for adding IPv4 addresses
    for address in addresses:
        # TODO IPv6 addresses
        network = str(ipaddress.ip_network(address, strict=False).network_address)
        cfg += f"/ip address add address={address} interface={interface_name} network={network}\n"
    return cfg

def generate_openwrt_interface_config(name, private_key, addresses, interface_name, listen_port=None):
    if interface_name is None:
        interface_name = name
    cfg = f"""config interface '{interface_name}'
        option proto 'wireguard'
        option private_key '{private_key}'\n"""
    for address in addresses:
        cfg += f"        list addresses '{address}'\n"
    if listen_port is not None:
        cfg += f"        option listen_port '{listen_port}'\n"
    return cfg + '\n'

def generate_mikrotik_peer_config(name, public_key, preshared_key, allowed_ips, interface_name, endpoint=None, keepalive=60, provides_routes=[], addresses=[]):
    peerConfig = f"""/interface wireguard peers add interface={interface_name} allowed-address={','.join(allowed_ips)} public-key=\"{public_key}\" comment=\"{name}\""""
    if endpoint is not None:
        endpoint_address, _, endpoint_port = endpoint.rpartition(":")
        peerConfig += f" endpoint-address={endpoint_address} endpoint-port={endpoint_port}"
    if keepalive is not None:
        peerConfig += f" persistent-keepalive={keepalive}"
    if preshared_key is not None:
        peerConfig += f" preshared-key=\"{preshared_key}\""
    # Need to add routes manually !
    peer_addr = addresses[0].partition('/')[0] # 10.1.2.3/24 => 10.1.2.3 -- always use first address
    for route in provides_routes:
        # We removed comment="{interface_name} peer {name}" because it generates too much clutter
        peerConfig += f"""\n/ip route add check-gateway="ping" dst-address="{route}" gateway="{peer_addr}" """
    return peerConfig

def generate_openwrt_peer_config(name, public_key, preshared_key, allowed_ips, interface_name, endpoint=None, keepalive=60, provides_routes=[], addresses=[]):
    peerConfig = f"""config wireguard_{interface_name}
        option description '{name}'
        option public_key '{public_key}'
        option persistent_keepalive '{keepalive}'
        option route_allowed_ips '1'\n"""
    if endpoint is not None:
        endpoint_address, _, endpoint_port = endpoint.rpartition(":")
        peerConfig += f"        option endpoint_host '{endpoint_address}'\n"
        peerConfig += f"        option endpoint_port '{endpoint_port}'\n"
    for allowed_ip in allowed_ips:
        peerConfig += f"        list allowed_ips '{allowed_ip}'\n"
    return peerConfig + "\n"


def generate_peer_config(name, pubkey, preshared_key, allowed_ips=[], endpoint=None, keepalive=10):
    peerConfig = f"""[Peer]
# Name = {name}
PublicKey = {pubkey}
AllowedIPs = {', '.join(allowed_ips)}
PersistentKeepalive = {keepalive}\n"""
    if endpoint is not None:
        peerConfig += f"Endpoint = {endpoint}\n"
    if preshared_key is not None:
        peerConfig += f"PresharedKey = {preshared_key}\n"
    return peerConfig

def generate_or_load_peer_keys(config_name, peers):
    peer_keyset = {} # peer name to KeySet object
    for peer in peers:
        if peer.get("disabled", False):
            continue
        peer_name = peer['name']
        privkey_file, _, _ = key_filenames(config_name, peer_name)
        # Generate new key for that 
        if not os.path.isfile(privkey_file):
            logger.msg("Generating new key set for", peer=peer_name)
            generate_and_save_keys(config_name, peer_name)
        # Read keys
        peer_keyset[peer_name] = load_keys(config_name, peer_name)
    return peer_keyset

def get_keepalive(rules, type):
    return rules[type].get("keepalive", 30)

def is_reachable(peer):
    """
    Return true if the peer has an endpoint i.e.
    it is reachable from the outside.

    In other words, returns false for dynamic peers
    """
    return "endpoint" in peer

def is_any_reachable(peer1, peer2):
    """
    Return true if peer1 and/or peer2 is reachable,
    i.e. if peer and/or peer2 has an endpoint.

    If this returns False, it means that these peers
    can not reach each other because they don't know their addresses
    and hence can only communicate via routing.
    """
    return is_reachable(peer1) or is_reachable(peer2)

def should_connect_to(rules, our_type, peer_type):
    """
    Return true if a peer of type our_type should connect to
    based on the config connection rul
    """
    rule = rules[our_type].get("connect_to", ["*"])
    return ("*" in rule) or (peer_type in rule)

def is_ipv6(addr):
    return "::" in addr # TODO better way of checking if its an IPv6 addr

class KeySet(NamedTuple):
    private_key: str
    public_key: str
    psk: str

class SelfConfig(NamedTuple):
    """Configuration for the own interface"""
    config: object
    keys: KeySet

class RemotePeerConfig(NamedTuple):
    """Configuration for another peer to connect to (or that connects to us)"""
    name: str
    endpoint: str
    provides_routes: List[str]
    addresses: List[str]
    allowed_ips: List[str]
    use_psk: bool
    keys: KeySet

class ConfigInfo(NamedTuple):
    """Represents a config set from the viewpoint of a given interface"""
    me: SelfConfig
    peers: List[RemotePeerConfig]

class WireguardConfigurator(object):
    """Generates Wireguard configuration files for Mikrotik, OpenWRT and mobile clients"""

    def __init__(self, config_filename):
        self.config_filename = config_filename
        # Read config file
        with open(config_filename) as peers_file:
            config = json.load(peers_file)
            self.peers = config["peers"]
            self.rules = config["rules"]
        
        # Determine name (no extension) of config file
        self.config_name = os.path.splitext(config_filename)[0]

        # Create directories
        self.keys_dir = os.path.join(self.config_name, "keys")
        self.config_dir = os.path.join(self.config_name, "config")
        self.mikrotik_dir = os.path.join(self.config_name, "mikrotik")
        self.openwrt_dir = os.path.join(self.config_name, "openwrt")
        self.mobile_dir = os.path.join(self.config_name, "mobile")

    def generate_mikrotik_config(self, config_info: ConfigInfo):
        """Generate classical wireguard config"""
        me = config_info.me
        peers = config_info.peers

        listen_port = me.config.get("endpoint", "").partition(":")[-1] or None
        interface_name = me.config.get("interface_name") or me.config.get("name", "wireguard")

        config = generate_mikrotik_interface_config(
            me.config["name"],
            interface_name=interface_name,
            private_key=me.keys.private_key,
            addresses=me.config["addresses"],
            listen_port=listen_port)
        config = config.strip() + "\n"

        for peer in peers:
            keepalive = get_keepalive(self.rules, me.config["type"])
            config += generate_mikrotik_peer_config(
                name=peer.name,
                interface_name=interface_name,
                preshared_key=peer.keys.psk if peer.use_psk == True else None,
                public_key=peer.keys.public_key, allowed_ips=peer.allowed_ips,
                endpoint=peer.endpoint, keepalive=keepalive,
                provides_routes=peer.provides_routes,
                addresses=peer.addresses
            )
            config = config.strip() + "\n"

        config = config.strip() + "\n"
        # Write config to file
        with open(os.path.join(self.mikrotik_dir, f"{me.config['name']}.mik"), "w") as outfile:
            logger.msg("Exporting MikroTik commands for", peer=me.config['name'])
            outfile.write(config)

    def generate_openwrt_config(self, config_info: ConfigInfo):
        """Generate classical wireguard config"""
        me = config_info.me
        peers = config_info.peers

        listen_port = me.config.get("endpoint", "").partition(":")[-1] or None
        interface_name = me.config.get("interface_name") or me.config.get("name", "wireguard")

        config = generate_openwrt_interface_config(
            name=me.config["name"],
            interface_name=interface_name,
            private_key=me.keys.private_key,
            addresses=me.config["addresses"],
            listen_port=listen_port)
        config = config.strip() + "\n\n"

        for peer in peers:
            keepalive = get_keepalive(self.rules, me.config["type"])
            config += generate_openwrt_peer_config(
                name=peer.name,
                interface_name=interface_name,
                preshared_key=peer.keys.psk if peer.use_psk == True else None,
                public_key=peer.keys.public_key, allowed_ips=peer.allowed_ips,
                endpoint=peer.endpoint, keepalive=keepalive,
                provides_routes=peer.provides_routes,
                addresses=peer.addresses
            )
            config = config.strip() + "\n\n"

        config = config.strip() + "\n"
        # Write config to file
        with open(os.path.join(self.openwrt_dir, f"{me.config['name']}.cfg"), "w") as outfile:
            logger.msg("Exporting OpenWRT commands for", peer=me.config['name'])
            outfile.write(config)

    def generate_wg_config(self, config_info: ConfigInfo):
        """Generate classical wireguard config"""
        me = config_info.me
        peers = config_info.peers

        listen_port = me.config.get("endpoint", "").partition(":")[-1] or None
        addresses = ", ".join(me.config["addresses"])

        config = generate_interface_config(me.config["name"], private_key=me.keys.private_key, address=addresses, listen_port=listen_port)
        config += "\n\n"

        for peer in peers:
            # Generate standard wireguard config
            config += generate_peer_config(
                name=peer.name, pubkey=peer.keys.public_key,
                preshared_key=peer.keys.psk if peer.use_psk == True else None,
                allowed_ips=peer.allowed_ips, endpoint=peer.endpoint,
                keepalive=get_keepalive(self.rules, me.config["type"])
            )
            config += "\n\n"

        config = config.strip() + "\n"
        # Write config to file
        with open(os.path.join(self.config_dir, f"{me.config['name']}.conf"), "w") as outfile:
            logger.msg("Exporting config file for", peer=me.config['name'])
            outfile.write(config)

    def generate_mobile_qr(self, config_info: ConfigInfo):
        # We use qrencode to create the QR code from the normal WireGuard .conf
        config_filename = os.path.join(self.config_dir, f"{config_info.me.config['name']}.conf")
        png_filename = os.path.join(self.mobile_dir, f"{config_info.me.config['name']}.png")
        svg_filename = os.path.join(self.mobile_dir, f"{config_info.me.config['name']}.svg")
        logger.info("Exporting mobile QR code for", peer=config_info.me.config['name'], png=png_filename)
        try:
            # -d is DPI of the generated PNG
            try:
                subprocess.check_output(["qrencode", "-r", config_filename, "-o", png_filename, "-d", f"{72*4}"])
                subprocess.check_output(["qrencode", "-r", config_filename, "-o", svg_filename, "-d", f"{72*4}", "-t", "svg"])
            except subprocess.CalledProcessError as ex:
                logger.error("Could not generate QR code", ex=ex)
        except FileNotFoundError as ex:
            logger.error("Could not find qrencode executable", ex=ex)


    def generate_configs(self):
        # Read or generate keys for peers
        os.makedirs(self.keys_dir, exist_ok=True)
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.mikrotik_dir, exist_ok=True)
        os.makedirs(self.mobile_dir, exist_ok=True)
        os.makedirs(self.openwrt_dir, exist_ok=True)
        peer_keyset = generate_or_load_peer_keys(self.config_name, self.peers)

        # Iterate peer for which we will export config
        for me in self.peers:
            if me.get("disabled") == True:
                continue
            me_type = me["type"]
            me_keys = peer_keyset[me["name"]]

            me_peer = SelfConfig(config=me, keys=me_keys)

            me_other_peers = []

            # Generate peer config for ALL peers except self
            for other_peer in self.peers:
                # Ignore self
                if other_peer == me:
                    continue
                # Check if we should connect to the peer or the peer should connect to us
                # For example, mobile phones should not connect to other mobile phones
                # in order to keep the config small
                if not (should_connect_to(self.rules, me_type, other_peer["type"]) or should_connect_to(self.rules, other_peer["type"], me_type)):
                    continue
                # Also, we require that at least one of the peers is reachable. Otherwise, it doesn't make sense to list
                # the peer's key and traffic needs to be routed.
                if not is_any_reachable(me, other_peer):
                    continue
                # 
                other_peer_name = other_peer["name"]
                other_peer_keys = peer_keyset[other_peer_name]
                #
                # Compute allowed IPs
                #
                allowed_ips = list(other_peer.get('provides_routes', [])) # list(): copy list, instead we would modify the routes
                # Add route to peer's address
                for address in other_peer["addresses"]:
                    addr_only = address.rpartition("/")[0]
                    if is_ipv6(addr_only):
                        allowed_ips.append(f"{addr_only}/128")
                    else: # IPv4
                        allowed_ips.append(f"{addr_only}/32")
                allowed_ips = sorted(set(allowed_ips))

                me_other_peers.append(RemotePeerConfig(
                        name=other_peer.get("name"),
                        endpoint=other_peer.get("endpoint"),
                        use_psk=other_peer.get("use_psk", False) == True,
                        allowed_ips=allowed_ips,
                        keys=other_peer_keys,
                        provides_routes=other_peer.get("provides_routes", []),
                        addresses=other_peer.get("addresses", [])
                    )
                )
            # Processing for current peer is finished
            yield ConfigInfo(me_peer, peers=me_other_peers)

def prompt_yes_no(question, default=False):
    """Ask a yes/no question via input() and return True for yes."""
    default_str = "Y/n" if default else "y/N"
    try:
        resp = input(f"{question} [{default_str}]: ").strip().lower()
    except EOFError:
        return default
    if not resp:
        return default
    return resp in ("y", "yes")


def rename_device(config_filename, old_name, new_name, yes=False, dry_run=False):
    """Rename a device in the JSON config and associated files (keys/configs/images).

    Prompts before overwriting unless yes==True. If dry_run is True, simulate actions and do not modify files.
    """
    # Load JSON
    with open(config_filename) as f:
        data = json.load(f)

    peers = data.get("peers", [])
    idx = next((i for i, p in enumerate(peers) if p.get("name") == old_name), None)
    if idx is None:
        print(f"Device '{old_name}' not found in {config_filename}.")
        sys.exit(1)

    # Check for conflicting name
    existing_idx = next((i for i, p in enumerate(peers) if p.get("name") == new_name), None)
    if existing_idx is not None and existing_idx != idx:
        # If dry_run, we won't prompt interactively
        if not yes and not dry_run and not prompt_yes_no(f"A device named '{new_name}' already exists in {config_filename}. Overwrite it?", default=False):
            print("Aborted.")
            sys.exit(1)
        # Remove the existing entry to replace it (unless dry-run)
        if dry_run:
            print(f"Dry-run: would remove existing device entry '{new_name}' from JSON.")
            if existing_idx < idx:
                idx -= 1
        else:
            print(f"Removing existing device entry '{new_name}' from JSON.")
            peers.pop(existing_idx)
            if existing_idx < idx:
                idx -= 1

    cfg_base = os.path.splitext(config_filename)[0]
    dirs = {
        "keys": os.path.join(cfg_base, "keys"),
        "config": os.path.join(cfg_base, "config"),
        "mikrotik": os.path.join(cfg_base, "mikrotik"),
        "openwrt": os.path.join(cfg_base, "openwrt"),
        "mobile": os.path.join(cfg_base, "mobile"),
    }

    # Collect rename candidates
    rename_actions = []  # tuples (old, new)

    # Key files
    for suffix in (".privkey", ".pubkey", ".psk"):
        oldf = os.path.join(dirs["keys"], f"{old_name}{suffix}")
        newf = os.path.join(dirs["keys"], f"{new_name}{suffix}")
        if os.path.exists(oldf):
            rename_actions.append((oldf, newf))

    # Config files
    for d, ext in (("config", ".conf"), ("mikrotik", ".mik"), ("openwrt", ".cfg")):
        oldf = os.path.join(dirs[d], f"{old_name}{ext}")
        newf = os.path.join(dirs[d], f"{new_name}{ext}")
        if os.path.exists(oldf):
            rename_actions.append((oldf, newf))

    # Mobile images
    for ext in (".png", ".svg"):
        oldf = os.path.join(dirs["mobile"], f"{old_name}{ext}")
        newf = os.path.join(dirs["mobile"], f"{new_name}{ext}")
        if os.path.exists(oldf):
            rename_actions.append((oldf, newf))

    # Confirm if any destination exists
    for _, newf in rename_actions:
        if os.path.exists(newf) and not yes:
            if dry_run:
                print(f"Dry-run: target file '{newf}' already exists and would be overwritten.")
            else:
                if not prompt_yes_no(f"Target file '{newf}' already exists. Overwrite?", default=False):
                    print("Aborted.")
                    sys.exit(1)

    # Perform renames (or simulate)
    for oldf, newf in rename_actions:
        os.makedirs(os.path.dirname(newf), exist_ok=True)
        if dry_run:
            print(f"Dry-run: would rename {oldf} -> {newf}")
            continue
        try:
            shutil.move(oldf, newf)
            print(f"Renamed {oldf} -> {newf}")
        except Exception as e:
            print(f"Failed to rename {oldf} -> {newf}: {e}")

    # Update JSON
    peers[idx]["name"] = new_name

    if dry_run:
        print(f"Dry-run: would write changes to {config_filename} (rename '{old_name}' -> '{new_name}').")
        return

    if not yes and not prompt_yes_no(f"Write changes to {config_filename}?", default=False):
        print("Aborted.")
        sys.exit(1)

    with open(config_filename, "w") as f:
        json.dump(data, f, indent=4)

    print(f"Renamed device '{old_name}' -> '{new_name}' in {config_filename}.")


# --- Helpers for allocation when adding devices ---

def _collect_network_counters(peers):
    """Return counters of networks used in addresses for IPv4 and IPv6."""
    counters = {4: Counter(), 6: Counter()}
    for p in peers:
        for addr in p.get("addresses", []):
            try:
                net = ipaddress.ip_network(addr, strict=False)
            except Exception:
                continue
            counters[net.version][str(net.with_prefixlen)] += 1
    return counters


def _select_most_common_network(counter):
    """Given a Counter mapping network-with-prefix to counts, return an ip_network or None."""
    if not counter:
        return None
    most, _ = counter.most_common(1)[0]
    return ipaddress.ip_network(most, strict=False)


def _next_host_in_network(network, peers):
    """Find the first unused host IP in `network` given existing peers' addresses."""
    used = set()
    for p in peers:
        for addr in p.get("addresses", []):
            try:
                ip = ipaddress.ip_interface(addr).ip
            except Exception:
                continue
            if ip in network:
                used.add(int(ip))
    for host in network.hosts():
        if int(host) not in used:
            return f"{host}/{network.prefixlen}"
    return None


def _next_subnet_for_routes(peers):
    """Compute the next available subnet for provides_routes based on existing entries.

    Returns a string like '10.56.50.0/24' or None if not determinable.
    """
    routes = []
    for p in peers:
        for r in p.get("provides_routes", []):
            try:
                routes.append(ipaddress.ip_network(r, strict=False))
            except Exception:
                continue
    if not routes:
        return None
    # Choose most common prefixlen
    prefix_counter = Counter(r.prefixlen for r in routes)
    chosen_prefix = prefix_counter.most_common(1)[0][0]
    candidates = [r for r in routes if r.prefixlen == chosen_prefix]
    rep = candidates[0]
    # Find smallest supernet (closest to rep) that contains all candidates
    supernet = None
    for new_pref in range(rep.prefixlen - 1, -1, -1):
        try:
            cand = rep.supernet(new_prefix=new_pref)
        except Exception:
            continue
        if all(c.subnet_of(cand) for c in candidates):
            supernet = cand
            break
    if supernet is None:
        # fallback: use rep's supernet of size prefixlen-8 or the rep's immediate supernet
        try:
            supernet = rep.supernet(new_prefix=max(rep.prefixlen - 8, 0))
        except Exception:
            supernet = rep.supernet()

    # List subnets of the supernet with prefix chosen_prefix and find first unused
    used_set = set(str(r) for r in routes if r.prefixlen == chosen_prefix)
    for s in supernet.subnets(new_prefix=chosen_prefix):
        if str(s) not in used_set:
            return str(s)
    return None


def add_device(config_filename, name, type="Client", interface_name=None, addresses=None, provides_routes=None, yes=False, dry_run=False):
    """Add a new device to the JSON config with auto-assigned addresses and routes.

    Addresses or provides_routes passed explicitly (including an empty list) are used as-is.
    Auto-assignment only occurs when the corresponding argument is *None*.
    In particular, passing an empty ``provides_routes`` list disables route assignment.

    Prompts for confirmation (unless yes=True). Respects dry_run.
    """
    with open(config_filename, "r") as f:
        data = json.load(f)

    peers = data.setdefault("peers", [])
    existing_idx = next((i for i, p in enumerate(peers) if p.get("name") == name), None)

    if existing_idx is not None:
        if not yes and not prompt_yes_no(f"A device named '{name}' already exists. Overwrite it?", default=False):
            print("Aborted.")
            return

    # Auto compute addresses if not provided
    allocated_addresses = [] if addresses is None else list(addresses)
    counters = _collect_network_counters(peers)
    for ver in (4, 6):
        if addresses is not None and any((ipaddress.ip_network(a, strict=False).version == ver) for a in addresses):
            continue
        net = _select_most_common_network(counters[ver])
        if net is None:
            continue
        nh = _next_host_in_network(net, peers)
        if nh:
            allocated_addresses.append(nh)

    # Auto compute provides_routes only when the caller explicitly left it as None.
    # An empty list (``provides_routes`` == []) is treated as a deliberate request for
    # no routes and therefore no auto-assignment.
    allocated_routes = [] if provides_routes is None else list(provides_routes)
    if provides_routes is None:
        nr = _next_subnet_for_routes(peers)
        if nr:
            allocated_routes.append(nr)

    # construct new peer entry; omit provides_routes if empty to keep JSON clean
    new_peer = {
        "name": name,
        "addresses": allocated_addresses,
        "type": type,
    }
    if allocated_routes:
        new_peer["provides_routes"] = allocated_routes
    if interface_name:
        new_peer["interface_name"] = interface_name

    # Show summary and prompt
    print("New peer to add:")
    print(json.dumps(new_peer, indent=4, ensure_ascii=False))

    if not yes and not prompt_yes_no("Add this peer to the config?", default=False):
        print("Aborted.")
        return

    if dry_run:
        print("Dry-run: would append peer to the file but not write anything.")
        return

    # Append or replace existing
    if existing_idx is not None:
        peers[existing_idx] = new_peer
    else:
        peers.append(new_peer)

    # Write and format
    try:
        with open(config_filename, "w") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
            f.write("\n")
    except Exception as e:
        print(f"Failed to write '{config_filename}': {e}")
        sys.exit(1)

    # Ensure formatted (no prompt)
    format_json(config_filename, indent=4, yes=True, dry_run=False)

    print(f"Added peer '{name}' to {config_filename}.")


def format_json(config_filename, indent=4, yes=False, dry_run=False):
    """Pretty-format the JSON file with the requested indentation.

    If dry_run is True, print what would change but do not write.
    """
    # Read file
    try:
        with open(config_filename, "r") as f:
            orig = f.read()
    except Exception as e:
        print(f"Could not read '{config_filename}': {e}")
        sys.exit(1)

    try:
        data = json.loads(orig)
    except Exception as e:
        print(f"Could not parse JSON in '{config_filename}': {e}")
        sys.exit(1)

    new = json.dumps(data, indent=indent, ensure_ascii=False) + "\n"

    if new == orig:
        print(f"'{config_filename}' is already formatted (indent={indent}).")
        return

    if dry_run:
        print(f"Dry-run: would reformat '{config_filename}' (was {len(orig)} bytes, would be {len(new)} bytes)")
        return

    if not yes and not prompt_yes_no(f"Write formatted JSON to {config_filename}? (was {len(orig)} bytes, would be {len(new)} bytes)", default=False):
        print("Aborted.")
        sys.exit(1)

    try:
        with open(config_filename, "w") as f:
            f.write(new)
    except Exception as e:
        print(f"Failed to write '{config_filename}': {e}")
        sys.exit(1)

    print(f"Wrote formatted JSON to {config_filename} (indent={indent}).")


def list_clients(config_filename, all_types=False):
    """List clients in compact one-line format with aligned columns: name, addresses, provides_routes"""
    try:
        with open(config_filename) as f:
            data = json.load(f)
    except Exception as e:
        print(f"Could not read '{config_filename}': {e}")
        sys.exit(1)

    peers = data.get("peers", [])
    rows = []
    for p in peers:
        if p.get("disabled"):
            continue
        if not all_types and p.get("type") != "Client":
            continue
        name = p.get("name")
        addresses = p.get("addresses", [])
        provides_routes = p.get("provides_routes", [])
        addr_str = ",".join(addresses) if addresses else '(none)'
        routes_str = ",".join(provides_routes) if provides_routes else '(none)'
        rows.append((name, addr_str, routes_str))

    if not rows:
        return

    max_name = max(len(r[0]) for r in rows)
    max_addr = max(len(r[1]) for r in rows)

    for name, addr_str, routes_str in rows:
        print(f"{name.ljust(max_name)}  addresses:{addr_str.ljust(max_addr)}  provides_routes:{routes_str}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    # generate subcommand (default behaviour)
    genp = subparsers.add_parser("generate", help="Generate configurations from a JSON file")
    genp.add_argument("config", help="The config file to use")
    genp.add_argument("-q", "--qr", action="store_true", help="Generate QR codes for configs")
    genp.add_argument("-m", "--mikrotik", action="store_true")

    # rename subcommand
    renp = subparsers.add_parser("rename", help="Rename a device in the JSON config and associated files")
    renp.add_argument("config", help="The config file to modify")
    renp.add_argument("old_name", help="Current device name")
    renp.add_argument("new_name", help="New device name")
    renp.add_argument("-y", "--yes", action="store_true", help="Assume yes for all prompts")
    renp.add_argument("-n", "--dry-run", action="store_true", help="Preview renames without making changes")

    fmtp = subparsers.add_parser("format", help="Pretty-format a JSON config file")
    fmtp.add_argument("config", help="The config file to format")
    fmtp.add_argument("-i", "--indent", type=int, default=4, help="Indentation spaces (default: 4)")
    fmtp.add_argument("-y", "--yes", action="store_true", help="Assume yes for all prompts")
    fmtp.add_argument("-n", "--dry-run", action="store_true", dest="dry_run", help="Preview formatting without writing")

    # add subcommand
    addp = subparsers.add_parser("add", help="Add a new device to the JSON config")
    addp.add_argument("config", help="The config file to modify")
    addp.add_argument("name", help="Name of the device to add")
    addp.add_argument("-t", "--type", default="Client", help="Device type (Router/Client)")
    addp.add_argument("-I", "--interface-name", dest="interface_name", help="Interface name")
    addp.add_argument("--addresses", nargs="+", help="Explicit addresses (with CIDR). If omitted, auto-assigns next address(es)")
    addp.add_argument("--provides-routes", nargs="*", dest="provides_routes",
        help="Explicit provides_routes. If omitted, no routes will be added.\n"
             "The option may be given with no values to also request none.\n"
             "Auto-assignment occurs only when running the helper function directly with ``provides_routes=None``.")
    addp.add_argument("-y", "--yes", action="store_true", help="Assume yes for all prompts")
    addp.add_argument("-n", "--dry-run", action="store_true", dest="dry_run", help="Preview changes without writing")

    listp = subparsers.add_parser("list", help="List clients with their addresses and provided routes")
    listp.add_argument("config", help="The config file to use")
    listp.add_argument("-a", "--all", action="store_true", help="Include all device types (not only Clients)")

    args = parser.parse_args()

    # If no subcommand was provided, interpret the remaining argv as arguments for 'generate'
    # This ensures attributes like `config` are present on `args` (avoids AttributeError).
    if args.command is None:
        gen_args = genp.parse_args(sys.argv[1:])
        gen_args.command = "generate"
        args = gen_args

    if args.command == "generate":
        wg = WireguardConfigurator(args.config)
        configs = list(wg.generate_configs())
        for config in configs:
            wg.generate_wg_config(config)
            wg.generate_mikrotik_config(config)
            wg.generate_openwrt_config(config)
            wg.generate_mobile_qr(config)

        if getattr(args, "qr", False):
            # This line preserves existing behaviour, possibly intended to show a specific config QR
            subprocess.Popen(f"qrencode -t ansiutf8 < config/{args.qr}.conf", shell=True)
    elif args.command == "rename":
        rename_device(args.config, args.old_name, args.new_name, yes=args.yes, dry_run=getattr(args, "dry_run", False))
    elif args.command == "format":
        format_json(args.config, indent=getattr(args, "indent", 4), yes=args.yes, dry_run=getattr(args, "dry_run", False))
    elif args.command == "add":
        # CLI should never auto-assign routes when the user does not mention
        # ``--provides-routes`` at all.  The parser returns ``None`` in that
        # case, so convert to an explicit empty list here.  (Direct calls to
        # ``add_device`` may still pass ``None`` in order to trigger the
        # original auto-assignment behaviour.)
        pr = getattr(args, "provides_routes", None)
        if pr is None:
            pr = []
        add_device(
            args.config,
            args.name,
            type=getattr(args, "type", "Client"),
            interface_name=getattr(args, "interface_name", None),
            addresses=getattr(args, "addresses", None),
            provides_routes=pr,
            yes=args.yes,
            dry_run=getattr(args, "dry_run", False),
        )
    elif args.command == "list":
        list_clients(args.config, all_types=getattr(args, "all", False))
