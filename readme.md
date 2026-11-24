# jump
MCP proxy for HTTP APIs.

## Why
Giving agents access to APIs usually means installing or writing bespoke scripts or MCP servers, burning context on dozens of incomplete tool schemas and embedding raw API keys or OAuth tokens. Models already speak HTTP: `jump` turns any HTTP API into an MCP tool on the fly without wrapper code, holds the upstream credentials in one place and lets you hand out revocable, policy-scoped access to trusted agents, untrusted agents, scripts and teammates without exposing underlying credentials.

## How

* **Client sessions** - Sign in from an MCP client via OAuth (or a local bootstrap token). Mint revocable / non-admin sessions for other agents and scripts.
* **Upstream apps** - Each linked provider exposes one `<provider>_api` MCP tool:
	* **OAuth** - Ships with [`google`](providers/google.js) and [`github`](providers/github.js); adding a new config in [`providers/`](providers) is trivial (patches welcome).
	* **Static credentials** - Any HTTPS API at runtime using `Bearer`, `Basic`, custom HTTP `headers`, or `query` parameters.
* **Linking & sharing** - Link multiple apps to one session, fan one app across many sessions, or share apps with other users without exposing secrets.
* **Request policies** - Attach ordered `allow`/`deny` rules matching HTTP method, origin, path, query and body to any link or share.

## Install
```sh
$ git clone https://github.com/jessetane/jump.git
$ cd jump
$ npm i
$ cp .env.example .env
```

For upstream OAuth providers (`google`, `github`, etc.), register `https://<host>/oauth/callback` as the redirect URI in the provider's developer console and set `<PROVIDER>_CLIENT_ID` and `<PROVIDER>_CLIENT_SECRET` in `.env`. If no OAuth providers are configured, `jump` bootstraps a `localhost` admin bearer token on first startup and prints it to stdout.

On first run, `jump` auto-generates `<DB_PATH>.key` alongside the database unless an encryption key is configured; see [Security](#security) before deploying to production.

## Usage
Point an OAuth-capable MCP client at `https://<host>/mcp` and sign in as an admin:

```json
{
	"mcpServers": {
		"jump": {
			"serverUrl": "https://<host>/mcp"
		}
	}
}
```

From an admin session, use the `admin` tool to connect upstream apps, create scoped sessions and attach policies:

```javascript
// connect an OAuth provider (returns an interactive authorization URL; optional services pre-check permissions)
admin({ action: 'connect_app', provider: 'google', name: 'Work Google', services: ['gmail', 'calendar:read', 'calendar:write'] })

// or connect a static HTTP API via browser form (keeps API keys out of agent context)
admin({ action: 'connect_app', provider: 'stripe', name: 'Stripe', baseUrl: 'https://api.stripe.com' })

// or inline with Bearer shorthand or structured { bearer?, basic?, headers?, query? } credentials
admin({
	action: 'connect_app',
	provider: 'stripe',
	name: 'Stripe',
	credentials: 'sk_live_...',
	baseUrl: 'https://api.stripe.com'
})

// create a non-admin session for an embedded/untrusted agent (returns a bearer token)
admin({ action: 'create_session', name: 'Untrusted Agent' })

// link an app to that session with a path/method/query policy
admin({
	action: 'link_app',
	sessionId: '<session_id>',
	appId: '<app_id>',
	policy: [
		{
			action: 'allow',
			methods: ['GET'],
			path: '/calendar/v3/calendars/team@group.calendar.google.com'
		},
		{
			action: 'allow',
			path: '/calendar/v3/calendars/team@group.calendar.google.com/events/**',
			query: {
				sendUpdates: ['none', null]
			}
		}
	]
})

// share an app with another user under an optional ceiling policy
admin({
	action: 'share_app',
	appId: '<app_id>',
	account: 'teammate@example.com',
	policy: [{ action: 'allow', methods: ['GET'], path: '/v1/customers/**' }]
})
```

For headless or embedded installations, pass a bearer token (from `create_session` or `https://<host>/oauth/authorize`) in `headers`:

```json
{
	"mcpServers": {
		"jump": {
			"serverUrl": "https://<host>/mcp",
			"headers": {
				"Authorization": "Bearer <token>"
			}
		}
	}
}
```

## API

### MCP

* `<provider>_api({ url, method?, body?, headers?, app? })` - Proxies an HTTP request to a linked upstream app.
* `admin({ action, ... })` - Manages sessions, apps, shares, links, logins and usage logs (exposed on admin sessions):
	* `whoami` - Current user, linked logins, session info and linked apps.
	* `list_sessions` - List active sessions.
	* `get_session` - Get a session and its linked apps and policies.
	* `create_session` - Mint a new bearer session (and optionally link apps).
	* `update_session` - Rename a session, toggle `admin`, or rotate its token.
	* `revoke_session` - Revoke the current session, a specific session, or `allOthers`.
	* `list_apps` - List connected and shared apps.
	* `connect_app` - Connect an OAuth or static-credential upstream app (returns a browser setup URL when `credentials` are omitted, or re-authenticates / rotates credentials for `appId`).
	* `update_app` - Update an app's name or static credentials.
	* `disconnect_app` - Remove an app (and revoke its upstream OAuth token).
	* `share_app` - Share an owned app with another user under an optional ceiling policy.
	* `unshare_app` - Revoke an app share from a user.
	* `link_app` - Attach an app to a session with an optional policy.
	* `unlink_app` - Detach an app from a session.
	* `link_login` - Link an additional sign-in provider to the current user (or merge an existing account with `merge: true`).
	* `unlink_login` - Unlink a sign-in provider from the current user.
	* `list_logs` - Query proxied request audit logs.

### HTTP

```sh
# MCP & Static
GET    /                                        # landing page
GET    /style.css                               # shared ui stylesheet
POST   /mcp                                     # json-rpc mcp endpoint (also POST / and POST /mcp/*)

# OAuth & Discovery
GET    /.well-known/oauth-protected-resource    # rfc 9728 discovery
GET    /.well-known/oauth-authorization-server  # rfc 8414 discovery
POST   /oauth/register                          # rfc 7591 dynamic client registration
GET    /oauth/authorize                         # oauth / token sign-in screen
POST   /oauth/authorize/consent                 # oauth / token sign-in submission
GET    /oauth/verify                            # session activation & app selection screen
POST   /oauth/verify                            # session activation & app linking
POST   /oauth/token                             # oauth 2.0 pkce token exchange
POST   /oauth/revoke                            # rfc 7009 token revocation
GET    /oauth/callback                          # upstream oauth callback
GET    /apps/connect                            # static app credential form
POST   /apps/connect                            # static app credential submission
GET    /providers/:provider/connect             # upstream oauth scope selection
POST   /providers/:provider/consent             # upstream oauth redirect

# System & Identity
GET    /api/health                              # health check
GET    /api/whoami                              # session & linked apps info
POST   /api/logins                              # link sign-in provider (admin)
DELETE /api/logins/:id                          # unlink sign-in provider (admin)

# Sessions
GET    /api/sessions                            # list sessions (admin)
POST   /api/sessions                            # create session (admin)
DELETE /api/sessions?allOthers=true             # revoke all other sessions (admin)
GET    /api/sessions/:id                        # get session
PATCH  /api/sessions/:id                        # update session
DELETE /api/sessions/:id                        # revoke session

# Apps, Links & Shares
GET    /api/apps                                # list connected apps (admin)
POST   /api/apps                                # connect app (admin)
PATCH  /api/apps/:id                            # update app (admin)
DELETE /api/apps/:id                            # disconnect app (admin)
POST   /api/links                               # link app to session (admin)
DELETE /api/links?sessionId=...&appId=...       # unlink app from session (admin)
POST   /api/shares                              # share app with user (admin)
DELETE /api/shares?appId=...&account=...        # unshare app from user (admin)

# Audit & Upstream Proxy
GET    /api/logs                                # list usage logs (sessionId, appId, provider, allowed, limit)
ALL    /api/:provider/*                         # streaming rest proxy
```

For `ALL /api/:provider/*`, authenticate with your session `Authorization: Bearer <token>`, pass `X-Upstream-App: <id|name|account>` when multiple apps are linked for the same provider (stripped before forwarding), and pass upstream path/query parameters directly in the URL.

## Security

### Storage at rest
Jump-issued tokens and codes are stored as `SHA-256` digests, and upstream credentials are encrypted with `AES-256-GCM` + per-write `HKDF-SHA256` ([`crypto.js`](crypto.js), [`db/tokens.js`](db/tokens.js)). Keys load from systemd `$CREDENTIALS_DIRECTORY/jump.key`, `ENCRYPTION_KEY`, or `<DB_PATH>.key` (`0600`), with rotation via `.old` or `<new>,<old>`.

### Authentication & sessions
Client sign-in uses OAuth 2.1 with `S256` PKCE, `ALLOWED_REDIRECT_DOMAINS`, optional `OAUTH_PROVIDERS` role filtering (`auth` / `app`), and optional `SSO_DOMAINS` IdP pinning ([`oauth.js`](oauth.js), [`sso.js`](sso.js)). Non-admin sessions only see their linked `<provider>_api` tools and cannot inspect apps, policies, or other sessions ([`api/auth.js`](api/auth.js)).

### Upstream isolation & policies
Secrets never appear in tool schemas, API responses, or logs, and are stripped across cross-origin redirects ([`api/proxy.js`](api/proxy.js), [`mcp.js`](mcp.js)). Every hop resolves DNS against a private/metadata IP blocklist ([`util.js`](util.js)) and evaluates ordered `allow`/`deny` rules, with owner share policies enforced as an immutable ceiling ([`policy.js`](policy.js)).

### Network & reverse proxy
`jump` binds to `127.0.0.1` by default and resolves public URLs from `APP_URL` if set, or from `Host` (plus `X-Forwarded-*` on loopback connections). In production, set `APP_URL` or run behind a local reverse proxy that overwrites `Host` and `X-Forwarded-*`.

## Test
```sh
$ npm test
```

## License
MIT
