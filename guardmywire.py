#!/usr/bin/env python3
import subprocess
import os.path
import os
import ipaddress
import json
import argparse
from typing import NamedTuple, List
import structlog
from collections import namedtuple

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("config", help="The config file to use")
    parser.add_argument("-q", "--qr", action="store_true", help="Generate QR codes for configs")
    parser.add_argument("-m", "--mikrotik", action="store_true")
    args = parser.parse_args()

    wg = WireguardConfigurator(args.config)
    configs = list(wg.generate_configs())
    for config in configs:
        wg.generate_wg_config(config)
        wg.generate_mikrotik_config(config)
        wg.generate_openwrt_config(config)
        wg.generate_mobile_qr(config)

    if args.qr:
        subprocess.Popen(f"qrencode -t ansiutf8 < config/{args.qr}.conf", shell=True)
