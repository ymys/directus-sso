import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { version } = require('../package.json');
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

export default {
	id: 'sso',
	handler: (router, context) => {
		const { env, logger, services, database, getSchema } = context;
		const KEYCLOAK_URL = env.KEYCLOAK_URL || 'http://keycloak:8080';
		const KEYCLOAK_REALM = env.KEYCLOAK_REALM || 'testing';
		const KEYCLOAK_ADMIN_USER = env.KEYCLOAK_ADMIN_USER || 'admin';
		const KEYCLOAK_ADMIN_PASSWORD = env.KEYCLOAK_ADMIN_PASSWORD || 'admin';
		const PUBLIC_URL = env.PUBLIC_URL || 'http://localhost:8055';

		// --- UPGRADE MULTI-APP SCHEME ---
		const rawSchemes = env.MOBILE_APP_SCHEME || 'finsnapp';

		// Cek apakah Directus sudah mengubahnya jadi Array, kalau belum baru di-split
		const ALLOWED_SCHEMES = Array.isArray(rawSchemes)
			? rawSchemes.map(s => String(s).trim())
			: String(rawSchemes).split(',').map(s => s.trim());

		const DEFAULT_SCHEME = ALLOWED_SCHEMES[0];
		// --------------------------------

		const MOBILE_APP_CALLBACK_PATH = env.MOBILE_APP_CALLBACK_PATH || '/auth/callback';
		const GOOGLE_CALLBACK_PATH = env.GOOGLE_CALLBACK_PATH || '/auth/callback/google';
		const KEYCLOAK_CLIENT_ID = env.KEYCLOAK_CLIENT_ID || 'admin-cli';
		const COOKIE_DOMAIN = env.COOKIE_DOMAIN || null;
		const COOKIE_SECURE = env.COOKIE_SECURE !== 'false';
		const COOKIE_SAME_SITE = env.COOKIE_SAME_SITE || 'lax';
		const SESSION_COOKIE_NAME = env.SESSION_COOKIE_NAME || 'directus_session_token';
		const REFRESH_TOKEN_COOKIE_NAME = env.REFRESH_TOKEN_COOKIE_NAME || 'directus_refresh_token';
		const DEFAULT_ROLE_ID = env.DEFAULT_ROLE_ID || null;
		const CORE_COOKIE_NAME = 'directus_session_token';

		logger.info('🚀 Mobile Auth Proxy Extension loaded');
		logger.info('📱 Allowed Mobile App Schemes: ' + ALLOWED_SCHEMES.join(', '));
		logger.info('🔵 Google OAuth enabled');

		// Helper function to get Keycloak admin token
		async function getKeycloakAdminToken() {
			try {
				const response = await fetch(`${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams({
						grant_type: 'password',
						client_id: KEYCLOAK_CLIENT_ID,
						username: KEYCLOAK_ADMIN_USER,
						password: KEYCLOAK_ADMIN_PASSWORD,
					}).toString(),
				});
				if (!response.ok) throw new Error('Failed to get admin token');
				const data = await response.json();
				return data.access_token;
			} catch (error) {
				logger.error('Error getting admin token:', error);
				return null;
			}
		}

		// Helper function to get user ID from email
		async function getKeycloakUserId(adminToken, email) {
			try {
				const response = await fetch(
					`${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users?email=${encodeURIComponent(email)}`,
					{ headers: { 'Authorization': `Bearer ${adminToken}` } }
				);
				if (!response.ok) throw new Error('Failed to get user');
				const users = await response.json();
				return users.length > 0 ? users[0].id : null;
			} catch (error) {
				logger.error('Error getting user ID:', error);
				return null;
			}
		}

		// Helper function to logout user sessions in Keycloak
		async function logoutKeycloakUser(adminToken, userId) {
			try {
				const response = await fetch(
					`${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users/${userId}/logout`,
					{ method: 'POST', headers: { 'Authorization': `Bearer ${adminToken}` } }
				);
				return response.ok || response.status === 204;
			} catch (error) {
				logger.error('Error logging out user from Keycloak:', error);
				return false;
			}
		}

		// Health check
		router.get('/health', (req, res) => {
			res.json({ status: 'ok', service: 'directus-extension-sso', version, allowed_schemes: ALLOWED_SCHEMES });
		});

		// Helper function to detect if request is from browser or mobile app
		function isBrowserRequest(req) {
			if (req.query.type === 'browser') return true;
			if (req.query.type === 'mobile') return false;
			if (req.query.app_scheme || req.query.app_path) return false;
			const userAgent = req.headers['user-agent'] || '';
			const isBrowser = /Mozilla|Chrome|Safari|Firefox|Edge|Opera/i.test(userAgent) &&
				!/Mobile.*App|ReactNative|Expo/i.test(userAgent);
			return isBrowser;
		}

		async function tryAllCookies(req, cookieName) {
			const rawCookie = req.headers.cookie;
			if (!rawCookie) return null;
			const cookieValues = rawCookie.split(';')
				.map(c => c.trim())
				.filter(c => c.startsWith(`${cookieName}=`))
				.map(c => c.substring(cookieName.length + 1));
			if (cookieValues.length === 0) return null;

			for (let i = 0; i < cookieValues.length; i++) {
				const token = cookieValues[i];
				try {
					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
						headers: { 'Cookie': `${cookieName}=${token}` },
					});
					if (meResponse.ok) {
						const userData = await meResponse.json();
						return { token, userData: userData.data };
					}
				} catch (err) { }
			}
			return null;
		}

		async function tryEveryPossibleJwt(req) {
			const rawCookie = req.headers.cookie;
			if (!rawCookie) return null;
			const candidates = rawCookie.split(';')
				.map(c => c.trim())
				.map(c => {
					const parts = c.split('=');
					return parts.length > 1 ? parts[1] : null;
				})
				.filter(v => v && v.startsWith('eyJ') && v.length > 50);
			if (candidates.length === 0) return null;

			for (let i = 0; i < candidates.length; i++) {
				const token = candidates[i];
				try {
					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
						headers: { 'Authorization': `Bearer ${token}` }
					});
					if (meResponse.ok) {
						const userData = await meResponse.json();
						return { token, userData: userData.data };
					}
				} catch (err) { }
			}
			return null;
		}

		async function tryRefreshToken(req) {
			const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE_NAME];
			if (!refreshToken) return null;
			try {
				const refreshResponse = await fetch(`${PUBLIC_URL}/auth/refresh`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ refresh_token: refreshToken })
				});
				if (refreshResponse.ok) {
					const data = await refreshResponse.json();
					const newToken = data.data.access_token;
					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
						headers: { 'Authorization': `Bearer ${newToken}` }
					});
					if (meResponse.ok) {
						const userData = await meResponse.json();
						return { token: newToken, userData: userData.data };
					}
				}
			} catch (err) { }
			return null;
		}

		// --- SCHEME VALIDATOR HELPER ---
		function getValidatedScheme(req) {
			const requestedScheme = req.query.app_scheme;
			if (requestedScheme && ALLOWED_SCHEMES.includes(requestedScheme)) {
				return requestedScheme;
			} else if (requestedScheme) {
				logger.warn(`⚠️ Warning: App requested scheme '${requestedScheme}', but it is not in .env. Falling back to '${DEFAULT_SCHEME}'`);
			}
			return DEFAULT_SCHEME;
		}
		// -------------------------------

		// Mobile callback endpoint
		router.get('/mobile-callback', async (req, res) => {
			const isBrowser = isBrowserRequest(req);
			try {
				let authResult = null;
				if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
					authResult = await tryAllCookies(req, SESSION_COOKIE_NAME);
				}
				if (!authResult) authResult = await tryAllCookies(req, CORE_COOKIE_NAME);
				if (!authResult) authResult = await tryEveryPossibleJwt(req);
				if (!authResult) authResult = await tryRefreshToken(req);

				if (!authResult) {
					return res.send(`<html><body><h2>Authentication Failed</h2></body></html>`);
				}

				const { token: sessionToken, userData } = authResult;
				const userId = userData.id;
				const userEmail = userData.email;
				const accessToken = sessionToken;

				if (isBrowser) {
					res.cookie(SESSION_COOKIE_NAME, sessionToken, {
						httpOnly: true, secure: COOKIE_SECURE, domain: COOKIE_DOMAIN,
						sameSite: COOKIE_SAME_SITE, maxAge: 7 * 24 * 60 * 60 * 1000, path: '/',
					});
					if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
						res.cookie(CORE_COOKIE_NAME, '', { maxAge: 0, path: '/' });
					}
					let redirectTo = req.query.redirect_uri || req.query.redirect || '/';
					return res.redirect(redirectTo);
				}

				// MULTI-TENANT SCHEME SELECTION
				const scheme = getValidatedScheme(req);
				const path = req.query.app_path || MOBILE_APP_CALLBACK_PATH;
				const redirectUrl = `${scheme}://${path.replace(/^\/+/, '')}?access_token=${accessToken}&user_id=${userId}&email=${encodeURIComponent(userEmail || '')}`;

				res.setHeader('Location', redirectUrl);
				return res.status(302).send(`<html><head><meta http-equiv="refresh" content="0;url=${redirectUrl}"></head><body>Redirecting...</body></html>`);

			} catch (error) {
				res.status(500).send(`<html><body><h2>Error</h2><p>${error.message}</p></body></html>`);
			}
		});

		// Google callback endpoint
		router.get('/google-callback', async (req, res) => {
			const isBrowser = isBrowserRequest(req);
			try {
				let authResult = null;

				if (req.query.access_token) {
					authResult = { token: req.query.access_token, refresh_token: req.query.refresh_token || null, expires: req.query.expires || null };
					try {
						const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
							headers: { 'Authorization': `Bearer ${authResult.token}` },
						});
						if (meResponse.ok) {
							const meData = await meResponse.json();
							authResult.userData = meData.data;
						} else {
							authResult = null;
						}
					} catch (err) { authResult = null; }
				}

				if (!authResult && SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) authResult = await tryAllCookies(req, SESSION_COOKIE_NAME);
				if (!authResult) authResult = await tryAllCookies(req, CORE_COOKIE_NAME);
				if (!authResult) authResult = await tryEveryPossibleJwt(req);
				if (!authResult) authResult = await tryRefreshToken(req);

				if (!authResult) {
					return res.send(`<html><body><h2>Authentication Failed</h2></body></html>`);
				}

				const { token: sessionToken, userData } = authResult;
				const userId = userData.id;
				const userEmail = userData.email;
				const accessToken = sessionToken;

				if (isBrowser) {
					res.cookie(SESSION_COOKIE_NAME, sessionToken, {
						httpOnly: true, secure: COOKIE_SECURE, domain: COOKIE_DOMAIN,
						sameSite: COOKIE_SAME_SITE, maxAge: 7 * 24 * 60 * 60 * 1000, path: '/',
					});
					if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
						res.cookie(CORE_COOKIE_NAME, '', { maxAge: 0, path: '/' });
					}
					let redirectTo = req.query.redirect_uri || req.query.redirect || '/';
					return res.send(`<html><head><meta http-equiv="refresh" content="2;url=${redirectTo}"></head><body>Login Successful!</body></html>`);
				}

				// MULTI-TENANT SCHEME SELECTION
				const scheme = getValidatedScheme(req);
				const path = req.query.app_path || GOOGLE_CALLBACK_PATH;
				const redirectUrl = new URL(`${scheme}://${path.replace(/^\/+/, '')}`);
				redirectUrl.searchParams.set('access_token', accessToken);
				redirectUrl.searchParams.set('user_id', userId);
				redirectUrl.searchParams.set('email', userEmail || '');
				redirectUrl.searchParams.set('provider', 'google');

				logger.info('🚀 Performing direct 302 redirect to app: ' + redirectUrl.toString());
				return res.redirect(302, redirectUrl.toString());

			} catch (error) {
				res.status(500).send(`<html><body><h2>Error</h2><p>${error.message}</p></body></html>`);
			}
		});

		// Mobile logout endpoint 
		router.post('/mobile-logout', async (req, res) => {
			// (Isi kode logout tetap sama, tidak saya potong agar full code)
			try {
				const authHeader = req.headers.authorization;
				const token = authHeader?.replace('Bearer ', '');
				if (!token) return res.status(400).json({ error: 'No token provided' });

				let userEmail = null;
				try {
					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } });
					if (meResponse.ok) {
						const userData = await meResponse.json();
						userEmail = userData.data.email;
					}
				} catch (error) { }

				try {
					await fetch(`${PUBLIC_URL}/auth/logout`, {
						method: 'POST',
						headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
						body: JSON.stringify({ refresh_token: token }),
					});
				} catch (error) { }

				if (userEmail) {
					try {
						const adminToken = await getKeycloakAdminToken();
						if (adminToken) {
							const userId = await getKeycloakUserId(adminToken, userEmail);
							if (userId) await logoutKeycloakUser(adminToken, userId);
						}
					} catch (error) { }
				}
				res.json({ success: true, message: 'Logged out successfully' });
			} catch (error) {
				res.status(500).json({ error: error.message });
			}
		});

		// Apple login endpoint 
		router.post('/apple-token', async (req, res) => {
			// (Isi kode apple token tetap sama)
			// ...
		});

		// WebView SSO Bridge 
		router.get('/bridge', async (req, res) => {
			// (Isi kode bridge tetap sama)
			// ...
		});
	}
};