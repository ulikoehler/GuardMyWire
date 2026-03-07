# GuardMyWire
Generate WireGuard configuration files for Linux (`wg-quick`), OpenWRT and MikroTik platforms, and manage your peer definitions.

## Installation

1. Clone or download the repository and change into the project directory.
2. Install the Python dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Make sure the following utilities are available on your `$PATH`:
   * `wg` – required for key generation
   * `qrencode` – needed if you want mobile QR codes

   Without `wg` the script cannot function at all; without `qrencode` the mobile subcommand will be skipped.

## Configuration file

The tool operates on a JSON file with a `peers` list and `rules` section. Example configurations live in the [examples](https://github.com/ulikoehler/GuardMyWire/tree/master/examples) directory (e.g. [Site2Site.json](https://github.com/ulikoehler/GuardMyWire/blob/master/examples/Site2Site.json)).

## Usage

The main entry point is `guardmywire.py`. Running the script without an explicit subcommand defaults to **generate**.

```sh
python3 guardmywire.py <config.json>          # synonym for "generate"
python3 guardmywire.py generate <config.json>
```

### Generate
Create keys/configs for every peer defined in the JSON file.

```sh
python3 guardmywire.py generate my-config.json
# optional flags:
#   -q, --qr         generate mobile QR codes as PNG/SVG
#   -m, --mikrotik   only export MikroTik commands (skips other outputs)
```

Output directories (created alongside the JSON file base name):
* `keys/` – private, public and preshared keys
* `config/` – standard WireGuard `.conf` files
* `mikrotik/` – RouterOS terminal commands (`.mik`) for each interface
* `openwrt/` – UCI snippets (`.cfg`) for OpenWRT
* `mobile/` – QR codes (`.png`/`.svg`) for phone clients

### Other subcommands

* **rename** – change a peer name in the JSON and move associated files
  ```sh
  python3 guardmywire.py rename config.json oldname newname [-y] [-n]
  ```
  `-y` assumes yes for all prompts, `-n` performs a dry run.

* **add** – append (or replace) a peer entry, auto‑assigning addresses/routes if omitted
  ```sh
  python3 guardmywire.py add config.json peername [options]
  ```
  Options include `--type`, `--interface-name`, `--addresses`, `--provides-routes`, `-y`, `-n`.

* **format** – pretty‑print the JSON file
  ```sh
  python3 guardmywire.py format config.json [-i INDENT] [-y] [-n]
  ```

* **list** – show clients and their addresses/routes
  ```sh
  python3 guardmywire.py list config.json [-a]
  ```
  `-a` includes all device types instead of only "Client".

## Notes

* The script automatically creates its output directories if they don't exist.
* It will generate missing key pairs on demand and reuse existing ones.
* The `add` helper tries to pick sensible IPs based on networks already in use.

Feel free to read the source for more details about the configuration format and rules.
