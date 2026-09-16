# cpn

`cpn` — CLI/TUI utility for Ubuntu VPS hosts to inspect network status and manage subscription profiles. Optional explicit activation uses `sing-box` TUN full-tunnel mode.

## Install cpn

```bash
sudo install -Dm755 cpn.py /usr/local/lib/cpn/cpn.py
sudo install -Dm755 cpn /usr/local/bin/cpn
```

Install `sing-box` separately using the official package/repository for your Ubuntu release, then verify:

```bash
command -v sing-box
sing-box version
```

For SSH bypass and policy routing, install nftables and iproute2:

```bash
sudo apt-get update
sudo apt-get install -y nftables iproute2
```

Do not install a random binary from an untrusted subscription server.

## Commands

```text
cpn                         Open TUI
cpn status                  Show interface, IP, gateway, DNS, and connection state
cpn safety                  Show SSH/VPS activation safeguards
cpn add-subscription URL    Add an HTTPS subscription
cpn add-subscription URL --fetch  Add and immediately fetch profiles
cpn update                  Refresh saved subscriptions
cpn list                    List locally cached profiles
cpn select PROFILE_ID       Select a profile only; does not change networking
sudo cpn                    Open TUI with permission to activate VPN
sudo cpn select PROFILE_ID --activate  Select and activate full-tunnel VPN
sudo cpn deactivate         Stop VPN and restore the SSH route
```

## VPS / SSH safety model

Plain `cpn select PROFILE_ID` is non-mutating. In the TUI, choose **«Выбрать профиль»**, move with ↑/↓, and press Enter: the highlighted profile is saved and activated directly. Run the TUI as `sudo cpn` because activation requires root. Before starting sing-box, cpn resolves the SSH peer route and saves it. It installs a host route for that exact SSH client IP on the original interface, plus an nftables connection mark and policy route for **all TCP port-22 traffic**. This protects both the current SSH connection and new SSH connections from other IP addresses. The host route is stronger than excluding only port 22 for the current session because an established SSH flow can use an ephemeral source port, while the nftables rule covers the new-connection case. The VPN uses a TUN inbound with `auto_route` and a private-address direct rule; DNS is handled inside sing-box.

Activation is fail-closed: root is required; `sing-box check` must pass; `nft` must be installed; the systemd service must become active; and the SSH peer route must still resolve to the original interface after TUN startup. Otherwise cpn disables the service and restores the saved SSH route, nftables table, policy rule, and policy route. Use `sudo cpn deactivate` to stop the service and restore the route. The first activation should be performed from a second SSH session or with VPS console access available because no software can guarantee connectivity against provider-level faults, invalid profiles, or an incorrectly packaged sing-box build.

## JSON subscription support

A subscription may return an array of Xray JSON configurations. cpn recognizes objects containing an `outbounds` array and stores them as `xray-json` profiles. At activation time it converts the first non-service outbound from these protocols:

- VLESS (`vnext`, including TLS, Reality, WebSocket, gRPC, and common xhttp fields);
- VMess (`vnext`, including common TLS/transport fields);
- Trojan (`servers`, including TLS/transport fields);
- Shadowsocks / Shadowsocks 2022 (`servers`).

The converter is data-only: it never executes JSON, JavaScript, shell commands, or provider-supplied routing rules. It intentionally ignores the source Xray DNS, inbounds, routing, and service outbounds, replacing them with cpn's controlled TUN/full-tunnel policy. Unsupported transports or missing required fields cause activation to fail before the service starts.

The current implementation does not yet convert Xray multiplex, KCP, QUIC, HTTP/2, or provider-specific custom fields. Such profiles remain importable but activation returns a clear error.

## Data and files

State is stored in `~/.config/cpn/state.json`; override locations with `CPN_CONFIG_DIR` and `CPN_DATA_DIR` for tests. Subscription responses may be JSON, line-based, or Base64-encoded links. Only HTTPS subscription URLs without embedded credentials are accepted. Downloaded profile content is parsed, never executed as code.

VPN files are written to `/etc/cpn/sing-box.json` and `/etc/cpn/ssh-route.json`; the service unit is `/etc/systemd/system/cpn-sing-box.service`.

## Prime Agent / harness

The full-tunnel policy is compatible with Prime Agent: HTTPS traffic to its installer, control plane, model provider, and Groq API is routed through the selected VPN profile. SSH bypass remains limited to TCP/22, so it does not interfere with Prime Agent's HTTPS traffic.

Install Prime Agent separately after activating the VPN, using its published installer:

```bash
curl --proto '=https' --proto-redir '=https' -fsSL https://app.primeintellect.ai/prime-agent/install.sh | sh
command -v prime-agent
prime-agent --help
```

Configure Groq without putting the key in this repository, the `cpn` state file, or a command-line argument:

```bash
read -rsp 'GROQ API key: ' GROQ_API_KEY
echo
export GROQ_API_KEY
```

List models currently available to that key:

```bash
curl -fsS https://api.groq.com/openai/v1/models \
  -H "Authorization: Bearer $GROQ_API_KEY" \
  -H 'Content-Type: application/json' \
  | python3 -c 'import json,sys; print("\\n".join(x["id"] for x in json.load(sys.stdin).get("data", [])))'
```

Use an ID returned by the API; Groq availability changes over time. For example, when present in the returned catalog:

```bash
prime-agent --provider groq --model 'openai/gpt-oss-20b'
```

Never put the key in a command-line argument or commit it. If Groq reports `401 Invalid API Key`, revoke the exposed key in Groq Console and create a replacement. If a model or quota error appears, choose another ID from the current `/models` response.
