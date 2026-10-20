# Browser Tokens sandbox proxy

A local egress proxy for testing [Browser Tokens](https://docs.evervault.com/browser-tokens) from your own IP address. Run it on your machine and set it as the egress proxy on browser tokens in a sandbox app, so merchants see your IP instead of a datacenter one.

> [!WARNING]
> For testing with sandbox apps only. Don't use it for production traffic.

```
browser ──▶ Evervault's browser proxy ──TLS──▶ <hostname>.<tailnet>.ts.net:443 (Tailscale Funnel) ──▶ this proxy ──▶ merchant
```

## How it works

The proxy is a single binary with [Tailscale Funnel](https://tailscale.com/kb/1223/funnel) built in, so you don't need to open ports on your network. It only accepts:

- connections from Evervault's browser proxy
- `CONNECT` requests with the password you set
- targets on the public internet, so a session can't reach your local network

It only carries encrypted traffic and never sees token values or plaintext.

## Requirements

- Docker, or a binary from [Releases](https://github.com/evervault/browser-tokens-sandbox-proxy/releases)
- A free Tailscale account
- An Evervault sandbox app with Browser Tokens enabled

## Set up Tailscale

These steps happen in the Tailscale admin console.

1. On the [DNS page](https://login.tailscale.com/admin/dns), turn on **MagicDNS** and **Enable HTTPS**.
2. In [Access controls](https://login.tailscale.com/admin/acls), add a `funnel` node attribute for `autogroup:member` on the **Node attributes** tab.
3. Create an [auth key](https://login.tailscale.com/admin/settings/keys). Leave it non-ephemeral and untagged.

## Run the proxy

Generate a password for the proxy and keep it for the browser token request:

```bash
export PROXY_PASSWORD="$(openssl rand -hex 24)"
echo "$PROXY_PASSWORD"

docker run -d --name evervault-sandbox-proxy --restart unless-stopped \
  -e TS_AUTHKEY=tskey-auth-... \
  -e PROXY_PASSWORD \
  -v evervault-sandbox-proxy:/state \
  ghcr.io/evervault/browser-tokens-sandbox-proxy:latest
```

`docker logs evervault-sandbox-proxy` shows the proxy's hostname, such as `evervault-sandbox-proxy.<tailnet>.ts.net`. The auth key is only needed on the first run, because the Tailscale node is stored in the volume.

Pin a version tag in place of `latest` to control when you update.

To run it without Docker, download a binary from [Releases](https://github.com/evervault/browser-tokens-sandbox-proxy/releases) and set the same variables.

## Use it with browser tokens

Set `proxySettings` when you [create browser tokens](https://docs.evervault.com/browser-tokens#create-browser-tokens):

```json
"proxySettings": {
  "type": "custom",
  "scheme": "https",
  "hostname": "evervault-sandbox-proxy.<tailnet>.ts.net",
  "port": 443,
  "username": "evervault",
  "password": "<PROXY_PASSWORD>"
}
```

Then [launch the browser session](https://docs.evervault.com/browser-tokens#launch-a-browser-session) as usual. To check it's working, request `https://ifconfig.me` through the session. The response should be your IP address.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `PROXY_PASSWORD` | | Required. The password Evervault's browser proxy sends. |
| `PROXY_USERNAME` | `evervault` | The username Evervault's browser proxy sends. |
| `TS_AUTHKEY` | | Needed on the first run. Without it, the logs show a Tailscale login link. |
| `TS_HOSTNAME` | `evervault-sandbox-proxy` | The Tailscale node name, which becomes the first part of the hostname. |
| `STATE_DIR` | `/state` in Docker | Where the Tailscale node is stored. |
| `ALLOWED_PORTS` | `443` | Comma-separated target ports. |
| `MAX_TUNNELS` | `256` | The most tunnels open at once. |
| `IDLE_TIMEOUT` | `5m` | Closes a tunnel with no traffic in either direction. |
| `MAX_TUNNEL_DURATION` | `1h` | Closes a tunnel regardless of traffic. |

## Verify the image

Images are signed with cosign and have build provenance attestations.

```bash
cosign verify ghcr.io/evervault/browser-tokens-sandbox-proxy:latest \
  --certificate-identity-regexp '^https://github.com/evervault/browser-tokens-sandbox-proxy/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/evervault/browser-tokens-sandbox-proxy:latest --owner evervault
```

## Troubleshooting

- **The logs show `refused reason="source not allowed"`.** Something other than Evervault's browser proxy connected. Expect this from scanners, because the hostname is public.
- **Startup fails with a Funnel or HTTPS error.** Check the HTTPS setting and node attribute from [Set up Tailscale](#set-up-tailscale).
- **The hostname doesn't resolve.** It usually appears within a minute. If not after ten, restart the container. Your own machine may cache the earlier failed lookup for a while.

## Limits

- Your proxy's hostname is public. The source allowlist and password protect it.
- Throughput is capped by your upload speed, and every request adds a round trip to your network.
- Merchants can still rate-limit or challenge a single IP address that runs many sessions.

## License

[MIT](LICENSE)
