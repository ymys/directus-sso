import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { version } = require('../package.json');
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

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

		// Apple Configuration
		const rawAppleClientIds = env.APPLE_CLIENT_ID || 'com.forumbandung.app';
		const APPLE_CLIENT_IDS = Array.isArray(rawAppleClientIds)
			? rawAppleClientIds.map(id => String(id).trim().toLowerCase())
			: String(rawAppleClientIds).split(',').map(id => id.trim().toLowerCase());
		const KEYCLOAK_CLIENT_ID = env.KEYCLOAK_CLIENT_ID || 'admin-cli';
		const COOKIE_DOMAIN = env.COOKIE_DOMAIN || null;
		const COOKIE_SECURE = env.COOKIE_SECURE !== 'false';
		const COOKIE_SAME_SITE = env.COOKIE_SAME_SITE || 'lax';
		const SESSION_COOKIE_NAME = env.SESSION_COOKIE_NAME || 'directus_session_token';
		const REFRESH_TOKEN_COOKIE_NAME = env.REFRESH_TOKEN_COOKIE_NAME || 'directus_refresh_token';
		const DEFAULT_ROLE_ID = env.DEFAULT_ROLE_ID || null;
		const CORE_COOKIE_NAME = 'directus_session_token';

		// Helper function to safely escape HTML characters
		function escapeHTML(str) {
			if (typeof str !== 'string') return '';
			return str.replace(/[&<>"']/g, (m) => {
				switch (m) {
					case '&': return '&amp;';
					case '<': return '&lt;';
					case '>': return '&gt;';
					case '"': return '&quot;';
					case "'": return '&#039;';
					default: return m;
				}
			});
		}

		// Helper function to validate redirect URL to prevent open redirect
		function getSafeRedirectUrl(url, fallback = '/') {
			if (!url || typeof url !== 'string') return fallback;

			try {
				// Allow deep link redirects for allowed mobile app schemes
				const hasAppScheme = ALLOWED_SCHEMES.some(scheme => url.startsWith(`${scheme}://`));
				if (hasAppScheme) {
					return url;
				}

				// 1. Relative URL check: Must start with / and must NOT start with // or /\ 
				if (url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\')) {
					return url;
				}

				// 2. Absolute URL check: Must match the origin of PUBLIC_URL
				const parsedUrl = new URL(url);
				const allowedOrigin = new URL(PUBLIC_URL).origin;

				if (parsedUrl.origin === allowedOrigin) {
					return url;
				}
			} catch (e) {
				// Fail silently and return fallback
			}

			logger.warn(`⚠️ Warning: Blocked potentially unsafe redirect URL: "${url}". Defaulting to fallback: "${fallback}"`);
			return fallback;
		}

		// Konfigurasi FCM (Firebase Cloud Messaging)
		const FCM_PROJECT_ID = env.FCM_PROJECT_ID || null;
		const FCM_CLIENT_EMAIL = env.FCM_CLIENT_EMAIL || null;
		const FCM_PRIVATE_KEY = env.FCM_PRIVATE_KEY ? env.FCM_PRIVATE_KEY.replace(/\\n/g, '\n') : null;
		const FCM_WEBHOOK_SECRET = env.FCM_WEBHOOK_SECRET || null;

		logger.info('🚀 Mobile Auth Extension loaded');
		logger.info('📱 Allowed Mobile App Schemes: ' + ALLOWED_SCHEMES.join(', '));

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
					redirectTo = getSafeRedirectUrl(redirectTo, '/');
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
					redirectTo = getSafeRedirectUrl(redirectTo, '/');
					const escapedRedirectTo = escapeHTML(redirectTo);
					return res.send(`<html><head><meta http-equiv="refresh" content="2;url=${escapedRedirectTo}"></head><body>Login Successful!</body></html>`);
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
		// Clear session cookies and redirect
		router.get('/logout-clear', (req, res) => {
			const cookieOptionsBase = {
				httpOnly: true,
				secure: COOKIE_SECURE,
				sameSite: COOKIE_SAME_SITE,
				path: '/',
			};

			// 1. Clear without domain (covers host-only cookies like adminfinx.goyong.in)
			res.clearCookie(SESSION_COOKIE_NAME, cookieOptionsBase);
			if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
				res.clearCookie(CORE_COOKIE_NAME, cookieOptionsBase);
			}
			res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, cookieOptionsBase);

			// 2. Clear with configured COOKIE_DOMAIN (covers domain-level cookies)
			if (COOKIE_DOMAIN) {
				const cookieOptionsWithDomain = { ...cookieOptionsBase, domain: COOKIE_DOMAIN };
				res.clearCookie(SESSION_COOKIE_NAME, cookieOptionsWithDomain);
				if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
					res.clearCookie(CORE_COOKIE_NAME, cookieOptionsWithDomain);
				}
				res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, cookieOptionsWithDomain);
			}

			// 3. Clear with explicit parent domain just in case (.goyong.in)
			try {
				res.clearCookie(SESSION_COOKIE_NAME, { ...cookieOptionsBase, domain: '.goyong.in' });
				res.clearCookie(CORE_COOKIE_NAME, { ...cookieOptionsBase, domain: '.goyong.in' });
				res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, { ...cookieOptionsBase, domain: '.goyong.in' });
			} catch (err) {}

			let redirectUrl = req.query.redirect;
			if (redirectUrl) {
				redirectUrl = getSafeRedirectUrl(redirectUrl, '/');
				logger.info(`🧹 Cleared cookies and redirecting to: ${redirectUrl}`);
				return res.redirect(redirectUrl);
			}
			logger.info(`🧹 Cleared cookies successfully (no redirect provided)`);
			return res.json({ success: true, message: 'Cookies cleared successfully' });
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

		// Delete user account and clear all active sessions
		router.post('/delete-account', async (req, res) => {
			try {
				const authHeader = req.headers.authorization;
				const token = authHeader?.replace('Bearer ', '');
				if (!token) return res.status(400).json({ error: 'No token provided' });

				// 1. Verify user token and get their profile
				let userId = null;
				let userEmail = null;
				try {
					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
						headers: { 'Authorization': `Bearer ${token}` }
					});
					if (meResponse.ok) {
						const userData = await meResponse.json();
						userId = userData.data.id;
						userEmail = userData.data.email;
					}
				} catch (error) {
					logger.error('[SSO] Error verifying token during account deletion:', error);
				}

				if (!userId || !userEmail) {
					return res.status(401).json({ error: 'Invalid or expired token' });
				}

				logger.info(`[SSO] Deleting account for user: ${userId} (${userEmail})`);

				// 2. FIRST: Invalidate all sessions BEFORE suspending the user.
				//    Suspending first causes /auth/logout to fail (INVALID_CREDENTIALS),
				//    which is exactly what was causing the browser re-login 401.

				// 2a. Extract the session token from the JWT payload and delete it directly.
				//     Querying by 'user' alone was returning 0 rows because Directus stores
				//     sessions keyed by the token value itself.
				let deletedSessionsCount = 0;
				try {
					const decoded = jwt.decode(token);
					const sessionToken = decoded?.session;
					if (sessionToken) {
						// Delete by the exact session token from the JWT payload
						const byToken = await database('directus_sessions')
							.where('token', sessionToken)
							.delete();
						deletedSessionsCount += byToken;
						logger.info(`[SSO] Deleted ${byToken} session(s) by token for user ${userId}`);
					}
					// Also delete any remaining sessions for this user (belt & suspenders)
					const byUser = await database('directus_sessions')
						.where('user', userId)
						.delete();
					deletedSessionsCount += byUser;
					logger.info(`[SSO] Deleted ${byUser} additional session(s) by user ID for ${userId}`);
				} catch (sessionError) {
					logger.error('[SSO] Error deleting sessions:', sessionError);
				}

				// 2b. Call Directus /auth/logout while the user is still active,
				//     so Directus can cleanly invalidate the session on its side.
				try {
					await fetch(`${PUBLIC_URL}/auth/logout`, {
						method: 'POST',
						headers: {
							'Authorization': `Bearer ${token}`,
							'Content-Type': 'application/json',
						},
						body: JSON.stringify({}),
					});
					logger.info(`[SSO] Directus /auth/logout called successfully for user ${userId}`);
				} catch (logoutError) {
					// Non-fatal: session rows already deleted above
					logger.warn('[SSO] /auth/logout call failed (non-fatal):', logoutError.message);
				}

				// 3. Now safe to suspend + anonymise the user record
				const { UsersService } = services;
				const schema = await getSchema();
				const usersService = new UsersService({ schema, knex: database });

				const timestamp = Date.now();
				const deletedEmail = `DELETED_${timestamp}_${userEmail}`;

				await usersService.updateOne(userId, {
					first_name: 'DELETED',
					last_name: 'ACCOUNT',
					status: 'suspended',
					email: deletedEmail,
					// Also clear the external_identifier so a new Google account
					// with the same email can be registered without conflicts.
					external_identifier: null,
					provider: 'default',
				});

				logger.info(`[SSO] Soft-deleted user ID ${userId} → email renamed to ${deletedEmail}, total sessions cleared: ${deletedSessionsCount}`);

				// 4. Logout from Keycloak if applicable
				try {
					const adminToken = await getKeycloakAdminToken();
					if (adminToken) {
						const keycloakUserId = await getKeycloakUserId(adminToken, userEmail);
						if (keycloakUserId) {
							await logoutKeycloakUser(adminToken, keycloakUserId);
							logger.info(`[SSO] Logged out user ${userEmail} from Keycloak`);
						}
					}
				} catch (keycloakError) {
					logger.error('[SSO] Error during Keycloak logout:', keycloakError);
				}

				return res.json({
					success: true,
					message: 'Account deleted successfully, sessions cleared.',
					sessions_cleared: deletedSessionsCount,
				});
			} catch (error) {
				logger.error('[SSO] Account deletion failed:', error);
				return res.status(500).json({ error: error.message, message: 'Failed to delete account' });
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
				const verifyAppleToken = async (idToken) => {
					const [headerB64, payloadB64, signatureB64] = idToken.split('.');
					const header = JSON.parse(Buffer.from(headerB64, 'base64').toString());
					const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());

					if (payload.iss !== 'https://appleid.apple.com') throw new Error('Invalid issuer');

					const allowedAudiences = [...APPLE_CLIENT_IDS, 'host.exp.exponent'];
					const actualAud = payload.aud.toLowerCase();

					if (!allowedAudiences.includes(actualAud)) {
						throw new Error(`Invalid audience: ${actualAud}. Allowed: ${allowedAudiences.join(', ')}`);
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

				// 1. First, try to find user by unique Apple ID (sub)
				let existingUsers = await usersService.readByQuery({ 
					filter: { 
						_and: [
							{ external_identifier: { _eq: sub } },
							{ provider: { _eq: 'apple' } }
						]
					} 
				});

				let user = existingUsers.length > 0 ? existingUsers[0] : null;

				// 2. If not found by Apple ID, try finding by email
				if (!user) {
					existingUsers = await usersService.readByQuery({ 
						filter: { email: { _eq: email } } 
					});
					
					if (existingUsers.length > 0) {
						user = existingUsers[0];
						// Link this existing email account to the Apple ID
						await usersService.updateOne(user.id, { 
							external_identifier: sub, 
							provider: 'apple' 
						});
					}
				}

				let userId;
				if (user) {
					userId = user.id;
				} else {
					// 3. Create new user if not found by either
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

		// Generate short-lived signed bridge token
		router.post('/bridge-token', async (req, res) => {
			try {
				const authHeader = req.headers.authorization;
				const token = authHeader?.replace('Bearer ', '');
				if (!token) return res.status(400).json({ error: 'No token provided' });

				// Verify token against /users/me
				const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
					headers: { 'Authorization': `Bearer ${token}` },
				});

				if (!meResponse.ok) return res.status(401).json({ error: 'Invalid token' });
				const userData = await meResponse.json();

				// Mint a short-lived bridge JWT
				const payload = {
					sub: userData.data.id,
					purpose: 'bridge',
				};
				const bridgeToken = jwt.sign(payload, env.SECRET, { expiresIn: '60s', issuer: 'directus-sso' });

				res.json({ success: true, bridge_token: bridgeToken });
			} catch (error) {
				res.status(500).json({ error: error.message });
			}
		});

		// WebView SSO Bridge 
		router.get('/bridge', async (req, res) => {
			const { token, bridge_token, redirect_uri, redirect } = req.query;
			const targetRedirect = getSafeRedirectUrl(redirect_uri || redirect, '/');

			const ENABLE_LEGACY_BRIDGE = env.ENABLE_LEGACY_BRIDGE === 'true';

			let userId = null;
			let finalToken = null;

			if (bridge_token) {
				try {
					const decoded = jwt.verify(bridge_token, env.SECRET, { issuer: 'directus-sso' });
					if (decoded.purpose !== 'bridge') {
						return res.status(400).json({ error: 'Invalid token purpose' });
					}
					userId = decoded.sub;

					// Generate a fresh session token for this user
					const payload = { id: userId, app_access: true, admin_access: false };
					finalToken = jwt.sign(payload, env.SECRET, { expiresIn: '7d', issuer: 'directus' });
				} catch (err) {
					return res.status(401).json({ error: 'Invalid or expired bridge token', message: err.message });
				}
			} else if (token && ENABLE_LEGACY_BRIDGE) {
				logger.warn('⚠️ Warning: Legacy bridge token used. This flow is vulnerable to session fixation.');
				try {
					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
						headers: { 'Authorization': `Bearer ${token}` },
					});
					if (!meResponse.ok) return res.status(401).json({ error: 'Invalid token' });
					const userData = await meResponse.json();
					userId = userData.data.id;
					finalToken = token;
				} catch (err) {
					return res.status(500).json({ error: 'Bridge failure', message: err.message });
				}
			} else {
				return res.status(400).json({ error: 'Secure bridge token required' });
			}

			// Set cookies and redirect
			res.cookie(SESSION_COOKIE_NAME, finalToken, {
				httpOnly: true, secure: COOKIE_SECURE, domain: COOKIE_DOMAIN,
				sameSite: COOKIE_SAME_SITE, maxAge: 7 * 24 * 60 * 60 * 1000, path: '/',
			});

			if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
				res.cookie(CORE_COOKIE_NAME, finalToken, {
					httpOnly: true, secure: COOKIE_SECURE, domain: COOKIE_DOMAIN,
					sameSite: COOKIE_SAME_SITE, maxAge: 7 * 24 * 60 * 60 * 1000, path: '/',
				});
			}

			return res.redirect(targetRedirect);
		});

	}
};