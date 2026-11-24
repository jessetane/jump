export default {
	id: 'google',
	name: 'Google',
	baseUrl: 'https://www.googleapis.com',
	allowedHosts: ['googleapis.com', '*.googleapis.com'],
	toolDescription: "Make HTTP requests directly to Google APIs (e.g. Drive, Docs, Sheets, Calendar, Gmail, Tasks) restricted to *.googleapis.com. Automatically attaches the user's Google OAuth Bearer token.",
	urlParamDescription: 'Full https://*.googleapis.com URL or relative path with optional query parameters (e.g. "drive/v3/files?pageSize=10", "calendar/v3/calendars/primary/events", or "https://sheets.googleapis.com/v4/spreadsheets/ID").',
	oauth: {
		authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
		tokenUrl: 'https://oauth2.googleapis.com/token',
		userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
		loginHintParam: 'login_hint',
		verifiedEmail: true,
		authParams: {
			access_type: 'offline',
			prompt: 'consent'
		},
		extractAccount (user) {
			if (user.verified_email === false) return null
			return (user.email || '').toLowerCase() || null
		},
		async revoke ({ token, fetch: fetchReq }) {
			await fetchReq('https://oauth2.googleapis.com/revoke', { form: { token } })
		},
		baseScopes: [
			'https://www.googleapis.com/auth/userinfo.email',
			'https://www.googleapis.com/auth/userinfo.profile'
		],
		services: {
			drive: {
				name: 'Google Drive',
				scopes: {
					read: [
						'https://www.googleapis.com/auth/drive.readonly',
						'https://www.googleapis.com/auth/drive.activity.readonly'
					],
					write: [
						'https://www.googleapis.com/auth/drive',
						'https://www.googleapis.com/auth/drive.activity'
					]
				}
			},
			docs: {
				name: 'Google Docs',
				scopes: {
					read: ['https://www.googleapis.com/auth/documents.readonly'],
					write: ['https://www.googleapis.com/auth/documents']
				}
			},
			sheets: {
				name: 'Google Sheets',
				scopes: {
					read: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
					write: ['https://www.googleapis.com/auth/spreadsheets']
				}
			},
			slides: {
				name: 'Google Slides',
				scopes: {
					read: ['https://www.googleapis.com/auth/presentations.readonly'],
					write: ['https://www.googleapis.com/auth/presentations']
				}
			},
			forms: {
				name: 'Google Forms',
				scopes: {
					read: ['https://www.googleapis.com/auth/forms.body.readonly'],
					write: ['https://www.googleapis.com/auth/forms.body']
				}
			},
			calendar: {
				name: 'Google Calendar',
				scopes: {
					read: ['https://www.googleapis.com/auth/calendar.readonly'],
					write: ['https://www.googleapis.com/auth/calendar']
				}
			},
			tasks: {
				name: 'Google Tasks',
				scopes: {
					read: ['https://www.googleapis.com/auth/tasks.readonly'],
					write: ['https://www.googleapis.com/auth/tasks']
				}
			},
			contacts: {
				name: 'Google Contacts',
				scopes: {
					read: ['https://www.googleapis.com/auth/contacts.readonly'],
					write: ['https://www.googleapis.com/auth/contacts']
				}
			},
			youtube: {
				name: 'YouTube',
				scopes: {
					read: [
						'https://www.googleapis.com/auth/youtube.readonly',
						'https://www.googleapis.com/auth/yt-analytics.readonly'
					],
					write: ['https://www.googleapis.com/auth/youtube']
				}
			},
			gmail: {
				name: 'Gmail',
				scopes: {
					read: ['https://www.googleapis.com/auth/gmail.readonly'],
					write: ['https://mail.google.com/']
				}
			},
			photos: {
				name: 'Google Photos',
				scopes: {
					read: [
						'https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata',
						'https://www.googleapis.com/auth/photospicker.mediaitems.readonly'
					],
					write: ['https://www.googleapis.com/auth/photoslibrary.appendonly']
				}
			},
			meet: {
				name: 'Google Meet',
				scopes: {
					read: ['https://www.googleapis.com/auth/meetings.space.readonly'],
					write: ['https://www.googleapis.com/auth/meetings.space.created']
				}
			},
			chat: {
				name: 'Google Chat',
				scopes: {
					read: [
						'https://www.googleapis.com/auth/chat.spaces.readonly',
						'https://www.googleapis.com/auth/chat.messages.readonly'
					],
					write: [
						'https://www.googleapis.com/auth/chat.spaces',
						'https://www.googleapis.com/auth/chat.messages'
					]
				}
			},
			search_console: {
				name: 'Google Search Console',
				scopes: {
					read: ['https://www.googleapis.com/auth/webmasters.readonly'],
					write: [
						'https://www.googleapis.com/auth/webmasters',
						'https://www.googleapis.com/auth/indexing'
					]
				}
			},
			analytics: {
				name: 'Google Analytics',
				scopes: {
					read: ['https://www.googleapis.com/auth/analytics.readonly'],
					write: [
						'https://www.googleapis.com/auth/analytics',
						'https://www.googleapis.com/auth/analytics.edit'
					]
				}
			},
			tag_manager: {
				name: 'Google Tag Manager',
				scopes: {
					read: ['https://www.googleapis.com/auth/tagmanager.readonly'],
					write: [
						'https://www.googleapis.com/auth/tagmanager.edit.containers',
						'https://www.googleapis.com/auth/tagmanager.edit.containerversions',
						'https://www.googleapis.com/auth/tagmanager.delete.containers',
						'https://www.googleapis.com/auth/tagmanager.publish',
						'https://www.googleapis.com/auth/tagmanager.manage.accounts',
						'https://www.googleapis.com/auth/tagmanager.manage.users'
					]
				}
			},
			postmaster: {
				name: 'Gmail Postmaster Tools',
				scopes: {
					read: ['https://www.googleapis.com/auth/postmaster.traffic.readonly'],
					write: ['https://www.googleapis.com/auth/postmaster']
				}
			},
			apps_script: {
				name: 'Google Apps Script',
				scopes: {
					read: [
						'https://www.googleapis.com/auth/script.projects.readonly',
						'https://www.googleapis.com/auth/script.deployments.readonly',
						'https://www.googleapis.com/auth/script.metrics',
						'https://www.googleapis.com/auth/script.processes'
					],
					write: [
						'https://www.googleapis.com/auth/script.projects',
						'https://www.googleapis.com/auth/script.deployments'
					]
				}
			},
			classroom: {
				name: 'Google Classroom',
				scopes: {
					read: [
						'https://www.googleapis.com/auth/classroom.courses.readonly',
						'https://www.googleapis.com/auth/classroom.rosters.readonly',
						'https://www.googleapis.com/auth/classroom.coursework.students.readonly',
						'https://www.googleapis.com/auth/classroom.coursework.me.readonly',
						'https://www.googleapis.com/auth/classroom.announcements.readonly',
						'https://www.googleapis.com/auth/classroom.courseworkmaterials.readonly',
						'https://www.googleapis.com/auth/classroom.topics.readonly'
					],
					write: [
						'https://www.googleapis.com/auth/classroom.courses',
						'https://www.googleapis.com/auth/classroom.rosters',
						'https://www.googleapis.com/auth/classroom.coursework.students',
						'https://www.googleapis.com/auth/classroom.coursework.me',
						'https://www.googleapis.com/auth/classroom.announcements',
						'https://www.googleapis.com/auth/classroom.courseworkmaterials',
						'https://www.googleapis.com/auth/classroom.topics'
					]
				}
			},
			books: {
				name: 'Google Books',
				scopes: {
					write: ['https://www.googleapis.com/auth/books']
				}
			},
			blogger: {
				name: 'Blogger',
				scopes: {
					read: ['https://www.googleapis.com/auth/blogger.readonly'],
					write: ['https://www.googleapis.com/auth/blogger']
				}
			},
			admin: {
				name: 'Google Admin',
				scopes: {
					read: [
						'https://www.googleapis.com/auth/admin.directory.user.readonly',
						'https://www.googleapis.com/auth/admin.directory.group.readonly',
						'https://www.googleapis.com/auth/admin.directory.domain.readonly',
						'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
						'https://www.googleapis.com/auth/admin.directory.device.mobile.readonly',
						'https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly',
						'https://www.googleapis.com/auth/admin.reports.audit.readonly',
						'https://www.googleapis.com/auth/admin.reports.usage.readonly',
						'https://www.googleapis.com/auth/apps.groups.settings',
						'https://www.googleapis.com/auth/apps.licensing',
						'https://www.googleapis.com/auth/cloud-identity.groups.readonly'
					],
					write: [
						'https://www.googleapis.com/auth/admin.directory.user',
						'https://www.googleapis.com/auth/admin.directory.group',
						'https://www.googleapis.com/auth/admin.directory.domain',
						'https://www.googleapis.com/auth/admin.directory.orgunit',
						'https://www.googleapis.com/auth/admin.directory.device.mobile',
						'https://www.googleapis.com/auth/admin.directory.device.chromeos',
						'https://www.googleapis.com/auth/admin.datatransfer',
						'https://www.googleapis.com/auth/apps.groups.settings',
						'https://www.googleapis.com/auth/apps.licensing',
						'https://www.googleapis.com/auth/cloud-identity.groups'
					]
				}
			}
		}
	}
}
