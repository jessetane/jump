# jump
MCP proxy for HTTP APIs.

## Why
Giving agents access to an API usually means installing or writing a bespoke MCP server per service, burning context on dozens of incomplete tool schemas and handing raw API keys or broad OAuth tokens straight to every client. Models already speak HTTP: `jump` turns any HTTP API into an MCP tool on the fly without wrapper code, holds the upstream credentials in one place, and lets you hand out revocable, policy-scoped access to trusted agents, untrusted agents, scripts, and teammates without ever exposing the underlying keys.

## How

* Connect built-in OAuth providers (`google`, `github`) or any HTTPS API (`Bearer`, `Basic`, or `?key=val` query auth) at runtime to expose a single `<provider>_api` MCP tool and matching `/api/:provider/*` HTTP proxy.
* Sessions are decoupled from upstream credentials: link multiple accounts (`work`, `personal`) to one session, fan one account out across many sessions, or share an app with another user (`share_app`) without sharing the secret.
* Ordered `allow`/`deny` policies on any link or share filter requests by HTTP method, origin, URL path glob, query parameters, and request body (`json` or `form` field maps, raw globs, or `null` for empty bodies).
* Built-in OAuth 2.1 + PKCE server for MCP clients (with optional `SSO_DOMAINS` pinning), falling back to a local bootstrap bearer token when run without OAuth providers.

## Setup
```sh
$ git clone https://github.com/jessetane/jump.git
$ cd jump
$ npm i
$ cp .env.example .env
```

For upstream OAuth providers (`google`, `github`, etc.), register `https://<host>/oauth/callback` as the redirect URI in the provider's developer console and set `<PROVIDER>_CLIENT_ID` and `<PROVIDER>_CLIENT_SECRET` in `.env`. If no OAuth providers are configured, `jump` bootstraps a `localhost` admin bearer token on first startup and prints it to stdout.

Set `SSO_DOMAINS=domain:provider[,domain:provider:strict]` to pin email domains to an authoritative OAuth provider (and optionally lock outbound sharing from that domain with `:strict`).

`jump` binds to `::1` by default and derives public URLs and client IPs from `Host` / `X-Forwarded-*` headers; in production, run it behind a trusted reverse proxy that sets and overwrites `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-For`.

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

From an admin session, use the `admin` tool to connect upstream apps, create scoped sessions, and attach policies:

```javascript
// connect an OAuth provider (returns an interactive authorization URL)
admin({ action: 'connect_app', provider: 'google', name: 'Work Google' })

// or connect any HTTP API with a Bearer key, Basic auth ("user:pass"), or query params ("?key=val")
admin({
	action: 'connect_app',
	provider: 'stripe',
	name: 'Stripe',
	apiKey: 'sk_live_...',
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

The same bearer token also works against the transparent HTTP proxy at `/api/:provider/*`:

```sh
$ curl -H "Authorization: Bearer <token>" https://<host>/api/stripe/v1/customers
```

## MCP

### Tools

* `<provider>_api({ url, method?, body?, headers?, account?, appId? })` - Proxies an HTTP request to the linked upstream provider.
* `admin({ action, ... })` - Manages sessions, apps, shares, links, login keys, and usage logs (`whoami`, `list_sessions`, `get_session`, `create_session`, `update_session`, `revoke_session`, `list_apps`, `connect_app`, `disconnect_app`, `update_app`, `share_app`, `unshare_app`, `link_app`, `unlink_app`, `link_login`, `unlink_login`, `list_logs`). Listed in `tools/list` for admin sessions.

## HTTP
```
POST   /mcp                                     # json-rpc mcp endpoint (also POST /)
GET    /style.css                               # shared ui stylesheet
GET    /oauth/authorize                         # oauth / token sign-in screen
POST   /oauth/authorize/consent                 # oauth / token sign-in submission
GET    /oauth/verify                            # session activation & app selection screen
POST   /oauth/verify                            # session activation & app linking
POST   /oauth/register                          # rfc 7591 dynamic client registration
POST   /oauth/token                             # oauth 2.0 pkce token exchange
POST   /oauth/revoke                            # rfc 7009 token revocation
GET    /oauth/callback                          # upstream oauth callback
GET    /providers/:provider/connect             # upstream oauth scope selection
POST   /providers/:provider/consent             # upstream oauth redirect
GET    /.well-known/oauth-protected-resource    # rfc 9728 discovery
GET    /.well-known/oauth-authorization-server  # rfc 8414 discovery
GET    /api/health                              # health check
GET    /api/whoami                              # session & linked apps info
POST   /api/logins                              # link sign-in provider (admin)
DELETE /api/logins                              # unlink sign-in provider (admin)
DELETE /api/logins/:id                          # unlink sign-in provider by id (admin)
GET    /api/sessions                            # list sessions (admin)
POST   /api/sessions                            # create session (admin)
DELETE /api/sessions                            # revoke session
GET    /api/sessions/:id                        # get session
PATCH  /api/sessions/:id                        # update session
DELETE /api/sessions/:id                        # revoke session
GET    /api/apps                                # list connected apps (admin)
POST   /api/apps                                # connect app (admin)
PATCH  /api/apps/:id                            # update app (admin)
DELETE /api/apps/:id                            # disconnect app (admin)
POST   /api/shares                              # share app with user (admin)
DELETE /api/shares                              # unshare app from user (admin)
POST   /api/links                               # link app to session (admin)
DELETE /api/links                               # unlink app from session (admin)
GET    /api/logs                                # list usage logs
ALL    /api/:provider/*                         # transparent rest proxy
```

## Test
```sh
$ npm test
```

## License
MIT
