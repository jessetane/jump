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
				ro: [
					'https://www.googleapis.com/auth/drive.readonly',
					'https://www.googleapis.com/auth/drive.activity.readonly'
				],
				rw: [
					'https://www.googleapis.com/auth/drive',
					'https://www.googleapis.com/auth/drive.activity'
				]
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
				ro: [
					'https://www.googleapis.com/auth/youtube.readonly',
					'https://www.googleapis.com/auth/yt-analytics.readonly'
				],
				rw: [
					'https://www.googleapis.com/auth/youtube',
					'https://www.googleapis.com/auth/yt-analytics.readonly'
				]
			},
			gmail: {
				name: 'Gmail',
				ro: ['https://www.googleapis.com/auth/gmail.readonly'],
				rw: ['https://mail.google.com/']
			},
			photos: {
				name: 'Google Photos',
				ro: [
					'https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata',
					'https://www.googleapis.com/auth/photospicker.mediaitems.readonly'
				],
				rw: [
					'https://www.googleapis.com/auth/photoslibrary.appendonly',
					'https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata',
					'https://www.googleapis.com/auth/photospicker.mediaitems.readonly'
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
			search_console: {
				name: 'Google Search Console',
				ro: ['https://www.googleapis.com/auth/webmasters.readonly'],
				rw: [
					'https://www.googleapis.com/auth/webmasters',
					'https://www.googleapis.com/auth/indexing'
				]
			},
			analytics: {
				name: 'Google Analytics',
				ro: ['https://www.googleapis.com/auth/analytics.readonly'],
				rw: [
					'https://www.googleapis.com/auth/analytics',
					'https://www.googleapis.com/auth/analytics.edit'
				]
			},
			tag_manager: {
				name: 'Google Tag Manager',
				ro: ['https://www.googleapis.com/auth/tagmanager.readonly'],
				rw: [
					'https://www.googleapis.com/auth/tagmanager.edit.containers',
					'https://www.googleapis.com/auth/tagmanager.edit.containerversions',
					'https://www.googleapis.com/auth/tagmanager.delete.containers',
					'https://www.googleapis.com/auth/tagmanager.publish',
					'https://www.googleapis.com/auth/tagmanager.manage.accounts',
					'https://www.googleapis.com/auth/tagmanager.manage.users'
				]
			},
			postmaster: {
				name: 'Gmail Postmaster Tools',
				ro: ['https://www.googleapis.com/auth/postmaster.traffic.readonly'],
				rw: ['https://www.googleapis.com/auth/postmaster']
			},
			apps_script: {
				name: 'Google Apps Script',
				ro: [
					'https://www.googleapis.com/auth/script.projects.readonly',
					'https://www.googleapis.com/auth/script.deployments.readonly',
					'https://www.googleapis.com/auth/script.metrics',
					'https://www.googleapis.com/auth/script.processes'
				],
				rw: [
					'https://www.googleapis.com/auth/script.projects',
					'https://www.googleapis.com/auth/script.deployments',
					'https://www.googleapis.com/auth/script.metrics',
					'https://www.googleapis.com/auth/script.processes'
				]
			},
			classroom: {
				name: 'Google Classroom',
				ro: [
					'https://www.googleapis.com/auth/classroom.courses.readonly',
					'https://www.googleapis.com/auth/classroom.rosters.readonly',
					'https://www.googleapis.com/auth/classroom.coursework.students.readonly',
					'https://www.googleapis.com/auth/classroom.coursework.me.readonly',
					'https://www.googleapis.com/auth/classroom.announcements.readonly',
					'https://www.googleapis.com/auth/classroom.courseworkmaterials.readonly',
					'https://www.googleapis.com/auth/classroom.topics.readonly'
				],
				rw: [
					'https://www.googleapis.com/auth/classroom.courses',
					'https://www.googleapis.com/auth/classroom.rosters',
					'https://www.googleapis.com/auth/classroom.coursework.students',
					'https://www.googleapis.com/auth/classroom.coursework.me',
					'https://www.googleapis.com/auth/classroom.announcements',
					'https://www.googleapis.com/auth/classroom.courseworkmaterials',
					'https://www.googleapis.com/auth/classroom.topics'
				]
			},
			books: {
				name: 'Google Books',
				ro: [],
				rw: ['https://www.googleapis.com/auth/books']
			},
			blogger: {
				name: 'Blogger',
				ro: ['https://www.googleapis.com/auth/blogger.readonly'],
				rw: ['https://www.googleapis.com/auth/blogger']
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
