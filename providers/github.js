export default {
	id: 'github',
	name: 'GitHub',
	baseUrl: 'https://api.github.com',
	oauth: {
		authUrl: 'https://github.com/login/oauth/authorize',
		tokenUrl: 'https://github.com/login/oauth/access_token',
		userInfoUrl: 'https://api.github.com/user',
		loginHintParam: 'login',
		extractAccount (user) {
			return user.login || null
		},
		async revoke ({ token, clientId, clientSecret, fetch: fetchReq }) {
			if (!clientId || !clientSecret) return
			await fetchReq(`https://api.github.com/applications/${clientId}/token`, {
				method: 'DELETE',
				headers: {
					authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
					accept: 'application/vnd.github+json',
					'content-type': 'application/json'
				},
				body: JSON.stringify({ access_token: token })
			})
		},
		baseScopes: ['read:user'],
		services: {
			repo: {
				name: 'Repositories',
				scopes: {
					read: ['public_repo'],
					write: ['repo']
				}
			},
			workflow: {
				name: 'GitHub Actions Workflows',
				scopes: {
					write: ['workflow']
				}
			},
			packages: {
				name: 'GitHub Packages',
				scopes: {
					read: ['read:packages'],
					write: ['write:packages'],
					delete: ['delete:packages']
				}
			},
			org: {
				name: 'Organizations & Teams',
				scopes: {
					read: ['read:org'],
					write: ['write:org'],
					admin: ['admin:org']
				}
			},
			project: {
				name: 'Projects',
				scopes: {
					read: ['read:project'],
					write: ['project']
				}
			},
			discussions: {
				name: 'Discussions',
				scopes: {
					read: ['read:discussion'],
					write: ['write:discussion']
				}
			},
			gist: {
				name: 'Gists',
				scopes: {
					write: ['gist']
				}
			},
			notifications: {
				name: 'Notifications',
				scopes: {
					read: ['notifications']
				}
			},
			user: {
				name: 'User Profile & Emails',
				scopes: {
					read: ['user:email'],
					write: ['user']
				}
			},
			gpg_key: {
				name: 'GPG Keys',
				scopes: {
					read: ['read:gpg_key'],
					write: ['write:gpg_key'],
					admin: ['admin:gpg_key']
				}
			},
			public_key: {
				name: 'SSH Keys',
				scopes: {
					read: ['read:public_key'],
					write: ['write:public_key'],
					admin: ['admin:public_key']
				}
			},
			repo_hook: {
				name: 'Repository Webhooks',
				scopes: {
					read: ['read:repo_hook'],
					write: ['write:repo_hook'],
					admin: ['admin:repo_hook']
				}
			},
			audit_log: {
				name: 'Audit Log',
				scopes: {
					read: ['read:audit_log']
				}
			},
			codespace: {
				name: 'Codespaces',
				scopes: {
					write: ['codespace']
				}
			}
		}
	}
}
