# jump
MCP jump host for HTTP APIs.

## Why
Most MCP servers wrap upstream APIs in dozens of rigid tools, burning context tokens on schemas while covering a fraction of the surface area. Upstream OAuth scopes are also too coarse (granting write access to a shared Google calendar lets an agent delete your personal calendar too), and agents shouldn't hold raw refresh tokens or master API keys directly.

Models already know REST APIs from pretraining—they just need an authenticated pipe with a firewall.

## How
* One `<provider>_api` passthrough tool per linked provider (`google_api`, `stripe_api`, etc).
* Sessions are decoupled from upstream OAuth and API-key credentials, so multiple accounts can be linked to one or many sessions.
* Each session-to-app link can carry an ordered `allow`/`deny` policy matching HTTP methods, origins, and URL path globs.

## Setup
```sh
$ git clone https://github.com/jessetane/jump.git
$ cd jump
$ npm i
$ cp .env.example .env
```

For Google OAuth, enable the APIs you want in Google Cloud Console, add `https://<host>/oauth/callback` to your OAuth client's redirect URIs, and set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`.

For magic-link emails, set `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, and `MAILGUN_SENDER` in `.env` (when unset, links are printed to stdout).

## Usage
Connect your MCP client directly via OAuth (`https://<host>/mcp`), or visit `https://<host>/oauth/authorize` to generate a bearer token:

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

From an admin session, use the `admin` tool to connect upstream apps and link them to sessions:

```javascript
// connect a Google account (returns an interactive OAuth URL)
admin({ action: 'connect_app', provider: 'google', name: 'Work Google' })

// or connect any REST API with an API key and baseUrl
admin({
	action: 'connect_app',
	provider: 'stripe',
	name: 'Stripe',
	apiKey: 'sk_live_...',
	baseUrl: 'https://api.stripe.com'
})

// link an app to a session with a path/method policy
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
			path: '/calendar/v3/calendars/team@group.calendar.google.com/events/**'
		}
	]
})
```

## MCP

### Tools
* `<provider>_api({ url, method?, body?, headers?, account?, appId? })` - Proxies an HTTP request to the linked upstream provider.
* `admin({ action, ... })` - Manages sessions, apps, and links (`whoami`, `list`, `get`, `create_session`, `update_session`, `revoke`, `list_apps`, `connect_app`, `disconnect_app`, `update_app`, `link_app`, `unlink_app`, `update_email`, `update_user`). Exposed only to admin sessions.

## HTTP
```
POST   /mcp                                     # json-rpc mcp endpoint (also POST /)
GET    /oauth/authorize                         # magic-link sign-in screen
POST   /oauth/authorize/consent                 # magic-link submission
GET    /oauth/verify                            # magic-link confirmation screen
POST   /oauth/verify                            # magic-link verification
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
POST   /api/links                               # link app to session (admin)
DELETE /api/links                               # unlink app from session (admin)
ALL    /api/:provider/*                         # transparent rest proxy
```

## Test
```sh
$ npm test
```

## License
MIT
