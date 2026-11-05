export default {
	id: 'github',
	name: 'GitHub',
	baseUrl: 'https://api.github.com',
	oauth: {
		authUrl: 'https://github.com/login/oauth/authorize',
		tokenUrl: 'https://github.com/login/oauth/access_token',
		userInfoUrl: 'https://api.github.com/user',
		extractAccount (user) {
			return user.login || null
		},
		async revoke ({ token, clientId, clientSecret }) {
			if (!clientId || !clientSecret) return
			await fetch(`https://api.github.com/applications/${clientId}/token`, {
				method: 'DELETE',
				headers: {
					authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
					accept: 'application/vnd.github+json',
					'content-type': 'application/json',
					'user-agent': 'jump'
				},
				body: JSON.stringify({ access_token: token })
			})
		},
		baseScopes: ['read:user'],
		services: {
			repo: {
				name: 'Repositories',
				ro: ['public_repo'],
				rw: ['repo']
			},
			workflow: {
				name: 'GitHub Actions Workflows',
				ro: [],
				rw: ['workflow']
			},
			packages: {
				name: 'GitHub Packages',
				ro: ['read:packages'],
				rw: ['read:packages', 'write:packages', 'delete:packages']
			},
			org: {
				name: 'Organizations & Teams',
				ro: ['read:org'],
				rw: ['write:org', 'admin:org']
			},
			project: {
				name: 'Projects',
				ro: ['read:project'],
				rw: ['project']
			},
			discussions: {
				name: 'Discussions',
				ro: ['read:discussion'],
				rw: ['write:discussion']
			},
			gist: {
				name: 'Gists',
				ro: [],
				rw: ['gist']
			},
			notifications: {
				name: 'Notifications',
				ro: ['notifications'],
				rw: []
			},
			user: {
				name: 'User Profile & Emails',
				ro: ['user:email'],
				rw: ['user']
			},
			gpg_key: {
				name: 'GPG Keys',
				ro: ['read:gpg_key'],
				rw: ['write:gpg_key', 'admin:gpg_key']
			},
			public_key: {
				name: 'SSH Keys',
				ro: ['read:public_key'],
				rw: ['write:public_key', 'admin:public_key']
			},
			repo_hook: {
				name: 'Repository Webhooks',
				ro: ['read:repo_hook'],
				rw: ['write:repo_hook', 'admin:repo_hook']
			},
			audit_log: {
				name: 'Audit Log',
				ro: ['read:audit_log'],
				rw: []
			},
			codespace: {
				name: 'Codespaces',
				ro: [],
				rw: ['codespace']
			}
		}
	}
}
