# jump
MCP jump host for upstream REST APIs.

## Why

* **Wrapper bloat**: Official and third-party MCP servers expose dozens or hundreds of rigid wrapper tools (`create_calendar_event`, `read_sheet_row`, `list_customers`). That burns thousands of context tokens on `tools/list` schemas while covering a fraction of the upstream API surface. Frontier models already know standard REST APIs from pretraining—they just need an authenticated HTTP pipe.  
* **Coarse OAuth scopes**: Upstream OAuth scopes (especially Google's) are dangerously broad. Granting an agent write access to manage a shared team calendar gives it permission to delete your primary personal calendar too.  
* **Credential isolation**: Agents shouldn't hold raw OAuth refresh tokens or master API keys on client machines.

`jump` solves all three: agents authenticate to the jump host with a scoped session token, call a single `<provider>_api` REST passthrough tool per linked provider, and `jump` enforces fine-grained HTTP method, origin, and path glob policies on every request before injecting upstream credentials.

## How

* **Two-tier token graph**: Gateway sessions (`provider = 'self'`) are decoupled from upstream app credentials (`provider = 'google' | 'stripe' | ...`, OAuth or API key). Multiple accounts from the same provider (e.g. personal and work Google accounts) can be linked to one or many sessions with independent policies.  
* **Dynamic `<provider>_api` tools**: `tools/list` dynamically exposes `<provider>_api` (e.g. `google_api`, `stripe_api`) only for providers linked to the caller's session, and `admin` only for sessions with admin privileges.  
* **Path/method policy firewall**: Each session-to-app link carries an ordered JSON policy (`allow`/`deny` by HTTP method, origin, and URL path globs with automatic percent-decoding and traversal prevention).

## Setup
```sh
$ git clone https://github.com/jessetane/jump.git
$ cd jump
$ npm install
$ cp .env.example .env
```

### Google OAuth Provider (Optional)
To connect Google accounts via interactive OAuth:

1. Enable the Google APIs you wish to use (Drive, Docs, Sheets, Slides, Forms, Calendar, Tasks, Keep, Meet, Gmail, Chat, Contacts, Photos, YouTube, etc.) in your Google Cloud project.  
2. Configure the OAuth consent screen.  
3. Create an OAuth 2.0 Client ID (Web application) and add `<APP_URL>/oauth/callback` to Authorized redirect URIs.  
4. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`.

### Email Delivery (Optional)
Set `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, and `MAILGUN_SENDER` in `.env` to send sign-in magic links via email. In local development (when unset), magic links are printed to stdout.

## Usage

### 1. Sign In & Create an Admin Session
Visit `<APP_URL>/oauth/authorize` in your browser, check **Admin Privileges**, and sign in via magic link (or connect directly via OAuth 2.0 PKCE + RFC 7591 Dynamic Client Registration from Claude Desktop, Antigravity, Cursor, or ChatGPT).

```json
{
	"mcpServers": {
		"jump": {
			"serverUrl": "<APP_URL>/mcp",
			"headers": {
				"Authorization": "Bearer <token>"
			}
		}
	}
}
```

### 2. Connect Upstream Apps & Link to Sessions
From an admin session, use the `admin` MCP tool (or REST API) to connect upstream OAuth or API-key apps and link them to worker sessions with fine-grained policies:

```javascript
// Connect a Google account (returns interactive OAuth URL)
admin({ action: 'connect_app', provider: 'google', name: 'Work Google' })

// Or connect any REST API with an API key and baseUrl
admin({
	action: 'connect_app',
	provider: 'stripe',
	name: 'Stripe Prod',
	account: 'acct_123',
	apiKey: 'sk_live_...',
	baseUrl: 'https://api.stripe.com'
})

// Link an app to a session with a default-deny path/method policy
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

## Tools

* **`<provider>_api`** (e.g. `google_api`, `stripe_api`): Dynamically exposed for each provider linked to the session.  
	* `url`: Full HTTPS URL or relative path with query parameters (e.g. `drive/v3/files?pageSize=10` or `/v1/customers`).  
	* `method`: `GET`, `POST`, `PUT`, `PATCH`, `DELETE` (defaults to `GET`).  
	* `body`: Object or string payload for `POST`/`PUT`/`PATCH` requests.  
	* `headers`: Optional extra request headers.  
	* `account` / `appId`: Optional account identifier, app name, or app ID when multiple accounts for the same provider are linked.  
* **`admin`**: Exposed only to sessions with `admin: true`.  
	* `action`: `'whoami'`, `'list'`, `'get'`, `'create_session'`, `'update_session'`, `'revoke'`, `'list_apps'`, `'connect_app'`, `'disconnect_app'`, `'update_app'`, `'link_app'`, `'unlink_app'`, `'update_email'`, `'update_user'`.

## Endpoints
```
POST   /mcp                                       # json-rpc mcp endpoint (also mounted at POST /)
GET    /oauth/authorize                           # magic-link sign-in & session creation screen
POST   /oauth/authorize/consent                   # magic-link request submission
GET    /oauth/verify                              # magic-link verification confirmation screen
POST   /oauth/verify                              # magic-link verification handler
POST   /oauth/register                            # rfc 7591 dynamic client registration
POST   /oauth/token                               # oauth 2.0 pkce token exchange
POST   /oauth/revoke                              # rfc 7009 token revocation
GET    /oauth/callback                            # upstream oauth callback handler
GET    /providers/:provider/connect               # upstream oauth scope selection & re-auth screen
POST   /providers/:provider/consent               # upstream oauth redirect
GET    /.well-known/oauth-protected-resource      # rfc 9728 discovery
GET    /.well-known/oauth-authorization-server    # rfc 8414 discovery
GET    /api/health                                # health check
GET    /api/whoami                                # inspect auth state, user, session & linked apps
GET    /api/sessions                              # list sessions (admin)
POST   /api/sessions                              # create session (admin)
DELETE /api/sessions                              # revoke current session (or ?allOthers=true)
GET    /api/sessions/:id                          # get session details
PATCH  /api/sessions/:id                          # update session name, admin flag, or rotate token
DELETE /api/sessions/:id                          # revoke session
GET    /api/apps                                  # list connected upstream apps (admin)
POST   /api/apps                                  # connect upstream app (admin)
PATCH  /api/apps/:id                              # update upstream app metadata (admin)
DELETE /api/apps/:id                              # disconnect upstream app (admin)
POST   /api/links                                 # link upstream app to session with policy (admin)
DELETE /api/links                                 # unlink upstream app from session (admin)
ALL    /api/:provider/*                           # transparent policy-enforced rest proxy
```

## Test
```sh
$ npm test
```

## License
MIT
