import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { version } = require('../package.json');
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { sendFCM } from './utils.js';

export default {
	id: 'sso',
	handler: (router, context) => {
		const { env, logger, services, database, getSchema } = context;

		// ==========================================
		// 1. KONFIGURASI ENVIRONMENT
		// ==========================================
		const KEYCLOAK_URL = env.KEYCLOAK_URL || 'http://keycloak:8080';
		const KEYCLOAK_REALM = env.KEYCLOAK_REALM || 'testing';
		const KEYCLOAK_ADMIN_USER = env.KEYCLOAK_ADMIN_USER || 'admin';
		const KEYCLOAK_ADMIN_PASSWORD = env.KEYCLOAK_ADMIN_PASSWORD || 'admin';
		const PUBLIC_URL = env.PUBLIC_URL || 'http://localhost:8055';

		// Multi-App Scheme
		const rawSchemes = env.MOBILE_APP_SCHEME || 'finsnapp';
		const ALLOWED_SCHEMES = Array.isArray(rawSchemes)
			? rawSchemes.map(s => String(s).trim())
			: String(rawSchemes).split(',').map(s => s.trim());
		const DEFAULT_SCHEME = ALLOWED_SCHEMES[0];

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

		// Konfigurasi FCM (Firebase Cloud Messaging)
		const FCM_PROJECT_ID = env.FCM_PROJECT_ID || null;
		const FCM_CLIENT_EMAIL = env.FCM_CLIENT_EMAIL || null;
		const FCM_PRIVATE_KEY = env.FCM_PRIVATE_KEY ? env.FCM_PRIVATE_KEY.replace(/\\n/g, '\n') : null;
		const FCM_WEBHOOK_SECRET = env.FCM_WEBHOOK_SECRET || null;

		logger.info('🚀 Mobile Auth & FCM Proxy Extension loaded');
		logger.info('📱 Allowed Mobile App Schemes: ' + ALLOWED_SCHEMES.join(', '));
		if (FCM_PROJECT_ID && FCM_PRIVATE_KEY) {
			logger.info('🔔 FCM Module: ENABLED for project ' + FCM_PROJECT_ID);
		} else {
			logger.warn('⚠️ FCM Module: DISABLED (Missing Credentials in .env)');
		}

		// ==========================================
		// 2. HELPER FUNCTIONS SSO
		// ==========================================
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

		function isBrowserRequest(req) {
			if (req.query.type === 'browser') return true;
			if (req.query.type === 'mobile') return false;
			if (req.query.app_scheme || req.query.app_path) return false;
			const userAgent = req.headers['user-agent'] || '';
			return /Mozilla|Chrome|Safari|Firefox|Edge|Opera/i.test(userAgent) &&
				!/Mobile.*App|ReactNative|Expo/i.test(userAgent);
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

		function getValidatedScheme(req) {
			const requestedScheme = req.query.app_scheme;
			if (requestedScheme && ALLOWED_SCHEMES.includes(requestedScheme)) {
				return requestedScheme;
			} else if (requestedScheme) {
				logger.warn(`⚠️ Warning: App requested scheme '${requestedScheme}', but it is not in .env. Falling back to '${DEFAULT_SCHEME}'`);
			}
			return DEFAULT_SCHEME;
		}

		// ==========================================
		// 3. ENDPOINTS API
		// ==========================================

		// Health check
		router.get('/health', (req, res) => {
			res.json({ status: 'ok', service: 'directus-extension-sso', version, allowed_schemes: ALLOWED_SCHEMES, fcm_enabled: !!FCM_PROJECT_ID });
		});

		// Mobile callback endpoint
		router.get('/mobile-callback', async (req, res) => {
			const isBrowser = isBrowserRequest(req);
			try {
				let authResult = null;
				if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) authResult = await tryAllCookies(req, SESSION_COOKIE_NAME);
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
			const { identityToken, firstName, lastName } = req.body;
			logger.info('🍎 Apple token exchange request received');

			if (!identityToken) {
				return res.status(400).json({
					error: 'identityToken is required',
					message: 'Apple identityToken must be provided in the request body'
				});
			}

			try {
				const clientID = 'com.forumbandung.app';

				const verifyAppleToken = async (idToken) => {
					const [headerB64, payloadB64, signatureB64] = idToken.split('.');
					const header = JSON.parse(Buffer.from(headerB64, 'base64').toString());
					const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());

					if (payload.iss !== 'https://appleid.apple.com') throw new Error('Invalid issuer');

					const allowedAudiences = [clientID.toLowerCase(), 'host.exp.exponent'];
					const actualAud = payload.aud.toLowerCase();

					if (!allowedAudiences.includes(actualAud)) {
						throw new Error('Invalid audience');
					}

					if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');

					const response = await fetch('https://appleid.apple.com/auth/keys');
					const { keys } = await response.json();
					const key = keys.find(k => k.kid === header.kid);
					if (!key) throw new Error('Apple public key not found');

					const keyObject = crypto.createPublicKey({ key: key, format: 'jwk' });
					const verify = crypto.createVerify('RSA-SHA256');
					verify.update(`${headerB64}.${payloadB64}`);

					const isValid = verify.verify(keyObject, signatureB64, 'base64url');
					if (!isValid) throw new Error('Invalid signature');

					return payload;
				};

				const decodedToken = await verifyAppleToken(identityToken);
				const { email, sub } = decodedToken;

				if (!email) throw new Error('Apple token did not contain an email');

				const { UsersService } = services;
				const schema = await getSchema();
				const usersService = new UsersService({ schema, knex: database });

				const existingUsers = await usersService.readByQuery({ filter: { email: { _eq: email } } });

				let userId;
				let user;
				if (existingUsers.length > 0) {
					user = existingUsers[0];
					userId = user.id;
					if (!user.external_identifier) {
						await usersService.updateOne(userId, { external_identifier: sub, provider: 'apple' });
					}
				} else {
					userId = await usersService.createOne({
						email,
						first_name: firstName || 'Apple User',
						last_name: lastName || '',
						role: DEFAULT_ROLE_ID,
						status: 'active',
						provider: 'apple',
						external_identifier: sub
					});
					user = await usersService.readOne(userId);
				}

				const payload = { id: userId, role: user.role || DEFAULT_ROLE_ID, app_access: true, admin_access: false };
				const sessionToken = jwt.sign(payload, env.SECRET, { expiresIn: '7d', issuer: 'directus' });
				const refreshTokenPayload = { id: userId, type: 'refresh' };
				const refreshToken = jwt.sign(refreshTokenPayload, env.SECRET, { expiresIn: '30d', issuer: 'directus' });

				res.json({
					success: true,
					data: { access_token: sessionToken, refresh_token: refreshToken, expires: 3600 * 24 * 7, user: user },
					user_id: userId,
					email: email,
					provider: 'apple'
				});
			} catch (error) {
				res.status(500).json({ error: error.message, message: 'Failed to verify Apple token' });
			}
		});

		// WebView SSO Bridge 
		router.get('/bridge', async (req, res) => {
			const { token, redirect_uri, redirect } = req.query;
			const targetToken = token;
			const targetRedirect = redirect_uri || redirect || '/';

			if (!targetToken) return res.status(400).json({ error: 'Token required', message: 'No access token provided' });

			try {
				const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
					headers: { 'Authorization': `Bearer ${targetToken}` },
				});

				if (!meResponse.ok) return res.status(401).json({ error: 'Invalid token' });

				const userData = await meResponse.json();

				res.cookie(SESSION_COOKIE_NAME, targetToken, {
					httpOnly: true, secure: COOKIE_SECURE, domain: COOKIE_DOMAIN,
					sameSite: COOKIE_SAME_SITE, maxAge: 7 * 24 * 60 * 60 * 1000, path: '/',
				});

				if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
					res.cookie(CORE_COOKIE_NAME, targetToken, {
						httpOnly: true, secure: COOKIE_SECURE, domain: COOKIE_DOMAIN,
						sameSite: COOKIE_SAME_SITE, maxAge: 7 * 24 * 60 * 60 * 1000, path: '/',
					});
				}

				return res.redirect(targetRedirect);
			} catch (error) {
				res.status(500).json({ error: 'Bridge failure', message: error.message });
			}
		});

		// ==========================================
		// 4. ENDPOINT FCM PUSH NOTIFICATIONS
		// ==========================================

		router.post('/send-fcm', async (req, res) => {
			const authSecret = req.headers['x-fcm-secret'];
			if (FCM_WEBHOOK_SECRET && authSecret !== FCM_WEBHOOK_SECRET) {
				logger.warn('🚨 Percobaan akses FCM Endpoint ditolak (Secret tidak cocok/hilang)');
				return res.status(401).json({ error: 'Unauthorized. Cek header x-fcm-secret.' });
			}

			const { tokens, title, body, metadata } = req.body;
			if (!tokens || !Array.isArray(tokens) || tokens.length === 0) {
				return res.status(400).json({ error: 'Payload harus memiliki array "tokens".' });
			}

			try {
				const results = await sendFCM(env, { tokens, title, body, metadata, logger });
				res.json({ success: true, sent_count: results.length, details: results });
			} catch (error) {
				logger.error('❌ Error mengirim notifikasi FCM:', error);
				res.status(500).json({ error: error.message });
			}
		});
	}
};