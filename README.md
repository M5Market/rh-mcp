# rh-mcp

Robinhood MCP proxy with integrated OAuth — a single-file, zero-dependency
bridge that lets any MCP client (ZCode, Claude Code, Cursor, etc.) talk to
Robinhood's OAuth-protected MCP server, **refreshing tokens automatically so
you never have to think about auth after the initial login.**

## The problem this solves

Robinhood's MCP server (`agent.robinhood.com/mcp/trading`) requires OAuth 2.1
(Authorization Code + PKCE). Most MCP clients don't initiate that flow — when
the server returns `401 authentication required`, the client just fails
instead of launching the OAuth handshake. The result: Robinhood's MCP appears
in your client's server list but never connects.

`rh-mcp` sits between your client and Robinhood, holds your OAuth tokens, and
refreshes them on demand:

```
MCP client ──stdio(NDJSON)──► rh-mcp serve ──http(+Bearer)──► Robinhood MCP
                                     │
                                     └─ on 401: refresh token, retry
```

Once you run `login` once, the proxy owns the entire auth lifecycle. When a
token expires, the next tool call triggers a transparent refresh — no manual
intervention, no scheduler, no expiry surprises.

## Quick start

**Prerequisites:** Python 3.9+ (standard library only — no pip installs).

```bash
# 1. Get the tool
curl -O https://raw.githubusercontent.com/<you>/rh-mcp/main/rh-mcp   # or git clone
chmod +x rh-mcp

# 2. Log in to Robinhood (opens browser, one-time)
./rh-mcp login

# 3. Point your MCP client at the proxy (see below), then restart it.
```

That's it. Your client will now have access to Robinhood's 44 tools:
`get_equity_historicals`, `get_equity_quotes`, `get_option_chains`,
`get_portfolio`, watchlists, scans, etc. — all with automatic auth.

## Client configuration

Add `rh-mcp` as a stdio MCP server. The exact config file differs by client;
the entry is always the same shape:

### ZCode

`~/.zcode/cli/config.json`:
```json
{
  "mcp": {
    "servers": {
      "robinhood": {
        "type": "stdio",
        "command": "/absolute/path/to/rh-mcp",
        "args": ["serve"]
      }
    }
  }
}
```

### Claude Code

`~/.claude.json` (or a project `.mcp.json`):
```json
{
  "mcpServers": {
    "robinhood": {
      "command": "/absolute/path/to/rh-mcp",
      "args": ["serve"]
    }
  }
}
```

### Cursor

Add to Settings → MCP:
```json
{
  "mcpServers": {
    "robinhood": {
      "command": "/absolute/path/to/rh-mcp",
      "args": ["serve"]
    }
  }
}
```

> **Use an absolute path.** MCP clients spawn the command from varying working
> directories; a relative path may not resolve.

After editing the config, restart your client. The `robinhood` server should
show as **connected**.

## Commands

| Command | Description |
|---------|-------------|
| `rh-mcp serve` | Run the stdio proxy. **This is what your MCP client spawns.** You don't run it manually. |
| `rh-mcp login` | Browser OAuth flow. Stores tokens in `~/.zcode/rh-mcp-creds.json`. Run once, or again to re-auth. |
| `rh-mcp login --install` | Log in, then also wire the stdio proxy into detected client configs. |
| `rh-mcp status` | Show token validity, expiry, and whether each detected client is wired. Tokens are redacted. |
| `rh-mcp self-test` | Verify internals (PKCE vectors, SSE parsing). No network. |

## How auth works

1. **`login`** runs the standard OAuth 2.1 Authorization Code + PKCE flow:
   generates a code verifier/challenge, opens your browser to
   `robinhood.com/oauth`, captures the redirect on `localhost:8765/callback`,
   and exchanges the code for access + refresh tokens. The CSRF `state`
   parameter is validated on callback.

2. **`serve`** loads the stored token and injects it as a `Bearer` header on
   every forwarded request. When Robinhood returns `401` (token expired,
   rotated, or revoked), the proxy refreshes using the stored refresh token
   and retries the request — transparently. If the refresh token is also
   invalid, it surfaces a clear JSON-RPC error telling you to run `login`.

3. **Token rotation** is handled: if Robinhood returns a new refresh token on
   refresh, it's persisted immediately.

## Why a proxy and not a scheduler?

A cron job refreshes on a timer that might fire too early (wasteful) or too
late (the token already expired and your session broke). A proxy refreshes
**lazily, exactly when needed** — the moment a real request hits a `401`. This
means:

- No background process to start at boot
- No timer to configure or drift
- Self-healing even if Robinhood revokes tokens or rotates them aggressively
- Zero wasted refresh calls when the proxy isn't being used

## Files

| Path | Purpose |
|------|---------|
| `~/.zcode/rh-mcp-creds.json` | Token store (chmod 0600, atomic writes) |
| `~/.zcode/rh-mcp-creds.lock` | File lock preventing concurrent login clobbering |
| `~/.zcode/rh-mcp.log` | Diagnostic log (refresh events, errors) |
| `~/.zcode/cli/config.json.bak` | Backup of your ZCode config before wiring |

## Troubleshooting

**`robinhood` server shows as failed / `authentication required`**
→ Your token expired and the proxy couldn't refresh. Run `rh-mcp login` again,
   then restart your client. Check `~/.zcode/rh-mcp.log` for the specific error.

**`rh-mcp status` says "not wired"**
→ Your client config doesn't point at the proxy. Re-run `rh-mcp login --install`
   or add the stdio config entry manually (see Client configuration above).

**Tools list is empty**
→ Run `rh-mcp self-test` to confirm the proxy works, then check the proxy log.
   Robinhood exposes 44 tools; if you see zero, the handshake failed.

**Port 8765 already in use during login**
→ Another process is using the callback port. Either stop it or edit
   `REDIRECT_PORT` in the script (and the matching `REDIRECT_URI`).

## Development

```bash
# Run the test suite (no network, no real auth)
python3 test_rh_mcp.py

# Verify the proxy end-to-end with real traffic
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' | ./rh-mcp serve
```

## Security notes

- Tokens are stored in `~/.zcode/rh-mcp-creds.json` (chmod 0600).
- `status` and logs redact tokens; the proxy never logs the token itself.
- The callback server only listens on loopback (`localhost`), not all interfaces.
- The `state` parameter guards against CSRF on the OAuth callback.
- Config writes are atomic (temp → fsync → rename) with a `.bak` backup, so a
  crash mid-write can't corrupt your MCP client config.

## License

MIT
