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
		authParams: {
			access_type: 'offline',
			prompt: 'consent'
		},
		extractAccount (user) {
			return (user.email || '').toLowerCase() || null
		},
		async revoke ({ token }) {
			await fetch('https://oauth2.googleapis.com/revoke', {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({ token }).toString()
			})
		},
		baseScopes: [
			'https://www.googleapis.com/auth/userinfo.email',
			'https://www.googleapis.com/auth/userinfo.profile'
		],
		services: {
			drive: {
				name: 'Google Drive',
				ro: ['https://www.googleapis.com/auth/drive.readonly'],
				rw: ['https://www.googleapis.com/auth/drive']
			},
			docs: {
				name: 'Google Docs',
				ro: ['https://www.googleapis.com/auth/documents.readonly'],
				rw: ['https://www.googleapis.com/auth/documents']
			},
			sheets: {
				name: 'Google Sheets',
				ro: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
				rw: ['https://www.googleapis.com/auth/spreadsheets']
			},
			slides: {
				name: 'Google Slides',
				ro: ['https://www.googleapis.com/auth/presentations.readonly'],
				rw: ['https://www.googleapis.com/auth/presentations']
			},
			forms: {
				name: 'Google Forms',
				ro: ['https://www.googleapis.com/auth/forms.body.readonly'],
				rw: ['https://www.googleapis.com/auth/forms.body']
			},
			calendar: {
				name: 'Google Calendar',
				ro: ['https://www.googleapis.com/auth/calendar.readonly'],
				rw: ['https://www.googleapis.com/auth/calendar']
			},
			tasks: {
				name: 'Google Tasks',
				ro: ['https://www.googleapis.com/auth/tasks.readonly'],
				rw: ['https://www.googleapis.com/auth/tasks']
			},
			contacts: {
				name: 'Google Contacts',
				ro: ['https://www.googleapis.com/auth/contacts.readonly'],
				rw: ['https://www.googleapis.com/auth/contacts']
			},
			youtube: {
				name: 'YouTube',
				ro: ['https://www.googleapis.com/auth/youtube.readonly'],
				rw: ['https://www.googleapis.com/auth/youtube']
			},
			gmail: {
				name: 'Gmail',
				ro: ['https://www.googleapis.com/auth/gmail.readonly'],
				rw: ['https://mail.google.com/']
			},
			photos: {
				name: 'Google Photos',
				ro: ['https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata'],
				rw: [
					'https://www.googleapis.com/auth/photoslibrary.appendonly',
					'https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata'
				]
			},
			meet: {
				name: 'Google Meet',
				ro: ['https://www.googleapis.com/auth/meetings.space.readonly'],
				rw: ['https://www.googleapis.com/auth/meetings.space.created']
			},
			chat: {
				name: 'Google Chat',
				ro: [
					'https://www.googleapis.com/auth/chat.spaces.readonly',
					'https://www.googleapis.com/auth/chat.messages.readonly'
				],
				rw: [
					'https://www.googleapis.com/auth/chat.spaces',
					'https://www.googleapis.com/auth/chat.messages'
				]
			},
			admin: {
				name: 'Google Admin',
				ro: [
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
				rw: [
					'https://www.googleapis.com/auth/admin.directory.user',
					'https://www.googleapis.com/auth/admin.directory.group',
					'https://www.googleapis.com/auth/admin.directory.domain',
					'https://www.googleapis.com/auth/admin.directory.orgunit',
					'https://www.googleapis.com/auth/admin.directory.device.mobile',
					'https://www.googleapis.com/auth/admin.directory.device.chromeos',
					'https://www.googleapis.com/auth/admin.datatransfer',
					'https://www.googleapis.com/auth/admin.reports.audit.readonly',
					'https://www.googleapis.com/auth/admin.reports.usage.readonly',
					'https://www.googleapis.com/auth/apps.groups.settings',
					'https://www.googleapis.com/auth/apps.licensing',
					'https://www.googleapis.com/auth/cloud-identity.groups'
				]
			}
		}
	}
}
