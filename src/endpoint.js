import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { version } = require('../package.json');
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { getShared } from './shared.js';

export default {
	id: 'sso',
	handler: (router, context) => {
		const { env, logger, services, database, getSchema } = context;

		const {
			ALLOWED_SCHEMES,
			DEFAULT_SCHEME,
			PUBLIC_URL,
			COOKIE_SECURE,
			COOKIE_SAME_SITE,
			SESSION_COOKIE_NAME,
			REFRESH_TOKEN_COOKIE_NAME,
			CORE_COOKIE_NAME,
			COOKIE_DOMAIN,
			MOBILE_APP_CALLBACK_PATH,
			getValidatedScheme,
			escapeHTML,
			renderFriendlyErrorPage
		} = getShared(env);

		async function ensureTempTable() {
			try {
				const hasTable = await database.schema.hasTable('sso_keycloak_tokens');
				if (!hasTable) {
					await database.schema.createTable('sso_keycloak_tokens', (table) => {
						table.string('code').primary();
						table.text('access_token');
						table.text('refresh_token');
						table.text('id_token');
						table.timestamp('created_at').defaultTo(database.fn.now());
					});
					logger.info('💾 Created temporary table sso_keycloak_tokens');
				} else {
					const hasIdToken = await database.schema.hasColumn('sso_keycloak_tokens', 'id_token');
					if (!hasIdToken) {
						await database.schema.alterTable('sso_keycloak_tokens', (table) => {
							table.text('id_token');
						});
						logger.info('💾 Added id_token column to sso_keycloak_tokens');
					}
				}
			} catch (err) {
				logger.error('⚠️ Failed to ensure sso_keycloak_tokens table:', err);
			}
		}
		ensureTempTable();

		// ==========================================
		// 1. KONFIGURASI ENVIRONMENT KEYCLOAK
		// ==========================================
		let parsedUrl = env.KEYCLOAK_URL;
		let parsedRealm = env.KEYCLOAK_REALM;
		if (env.AUTH_KEYCLOAK_ISSUER_URL) {
			try {
				const issuer = new URL(env.AUTH_KEYCLOAK_ISSUER_URL);
				if (!parsedUrl) parsedUrl = issuer.origin;
				if (!parsedRealm) {
					const parts = issuer.pathname.split('/');
					const realmIndex = parts.indexOf('realms');
					if (realmIndex !== -1 && parts[realmIndex + 1]) {
						parsedRealm = parts[realmIndex + 1];
					}
				}
			} catch (e) {
				logger.error('Error parsing AUTH_KEYCLOAK_ISSUER_URL:', e);
			}
		}

		const KEYCLOAK_URL = parsedUrl || 'http://keycloak:8080';
		const KEYCLOAK_REALM = parsedRealm || 'testing';
		const KEYCLOAK_ADMIN_USER = env.KEYCLOAK_ADMIN_USER || 'admin';
		const KEYCLOAK_ADMIN_PASSWORD = env.KEYCLOAK_ADMIN_PASSWORD || 'admin';

		const isKeycloakAdminConfigured = !!(
			(env.KEYCLOAK_URL || env.AUTH_KEYCLOAK_ISSUER_URL) &&
			env.KEYCLOAK_ADMIN_USER &&
			env.KEYCLOAK_ADMIN_PASSWORD
		);

		const GOOGLE_CALLBACK_PATH = env.GOOGLE_CALLBACK_PATH || '/auth/callback/google';

		// Apple Configuration
		const rawAppleClientIds = env.APPLE_CLIENT_ID || 'com.forumbandung.app';
		const APPLE_CLIENT_IDS = Array.isArray(rawAppleClientIds)
			? rawAppleClientIds.map(id => String(id).trim().toLowerCase())
			: String(rawAppleClientIds).split(',').map(id => id.trim().toLowerCase());
		const KEYCLOAK_CLIENT_ID = env.KEYCLOAK_CLIENT_ID || env.AUTH_KEYCLOAK_CLIENT_ID || 'admin-cli';
		const DEFAULT_ROLE_ID = env.DEFAULT_ROLE_ID || null;

		// Konfigurasi FCM (Firebase Cloud Messaging)
		const FCM_PROJECT_ID = env.FCM_PROJECT_ID || null;

		logger.info('🚀 Mobile Auth Extension Endpoint loaded');
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
						client_id: 'admin-cli',
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

		// Helper function to validate redirect URL to prevent open redirect
		function getSafeRedirectUrl(url, fallback = '/') {
			if (!url || typeof url !== 'string') return fallback;

			try {
				const hasAppScheme = ALLOWED_SCHEMES.some(scheme => url.startsWith(`${scheme}://`));
				if (hasAppScheme) {
					return url;
				}

				if (url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\')) {
					return url;
				}

				const parsedUrl = new URL(url);
				const allowedOrigin = new URL(PUBLIC_URL).origin;

				if (parsedUrl.origin === allowedOrigin) {
					return url;
				}
			} catch (e) {
				// Fail silently
			}

			logger.warn(`⚠️ Warning: Blocked potentially unsafe redirect URL: "${url}". Defaulting to fallback: "${fallback}"`);
			return fallback;
		}

		// ==========================================
		// 3. ENDPOINTS API
		// ==========================================

		// Health check
		router.get('/health', (req, res) => {
			res.json({ status: 'ok', service: 'directus-extension-sso', version, allowed_schemes: ALLOWED_SCHEMES, fcm_enabled: !!FCM_PROJECT_ID });
		});

		// Server-side redirect helper to reliably return to custom mobile app deep links
		router.get('/return', (req, res) => {
			const redirectUri = req.query.redirect_uri || req.query.redirect;
			if (redirectUri) {
				logger.info(`🔄 Server-side redirecting back to app via 302: ${redirectUri}`);
				return res.redirect(302, redirectUri);
			}
			return res.status(400).send('Missing redirect_uri');
		});

		// Initiate Keycloak OIDC login flow directly through the extension
		router.get('/login/keycloak', (req, res) => {
			const scheme = getValidatedScheme(req);
			const path = req.query.app_path || MOBILE_APP_CALLBACK_PATH;
			
			res.cookie('sso_mobile_redirect', JSON.stringify({ scheme, path }), {
				httpOnly: true,
				secure: COOKIE_SECURE,
				sameSite: COOKIE_SAME_SITE,
				maxAge: 15 * 60 * 1000, // 15 mins
				path: '/',
			});

			const redirectUri = `${PUBLIC_URL}/sso/keycloak-callback`;
			const keycloakAuthUrl = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth?` +
				new URLSearchParams({
					client_id: KEYCLOAK_CLIENT_ID,
					redirect_uri: redirectUri,
					response_type: 'code',
					scope: 'openid email profile',
					state: crypto.randomBytes(16).toString('hex')
				}).toString();

			logger.info(`🔐 Redirecting user to Keycloak: ${keycloakAuthUrl}`);
			res.redirect(keycloakAuthUrl);
		});

		// Keycloak OIDC callback endpoint
		router.get('/keycloak-callback', async (req, res) => {
			const { code } = req.query;
			if (!code) {
				logger.error('❌ Keycloak Callback: Missing code in query parameters');
				return res.status(400).send('Missing authorization code');
			}

			try {
				const redirectUri = `${PUBLIC_URL}/sso/keycloak-callback`;
				const tokenUrl = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;
				
				const clientSecret = env.KEYCLOAK_CLIENT_SECRET || env.AUTH_KEYCLOAK_CLIENT_SECRET || '';

				logger.info(`🔄 Exchanging authorization code at Keycloak token endpoint...`);

				const tokenParams = {
					grant_type: 'authorization_code',
					client_id: KEYCLOAK_CLIENT_ID,
					code,
					redirect_uri: redirectUri,
				};

				if (clientSecret) {
					tokenParams.client_secret = clientSecret;
				}

				const tokenResponse = await fetch(tokenUrl, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams(tokenParams).toString()
				});

				if (!tokenResponse.ok) {
					const errText = await tokenResponse.text();
					logger.error(`❌ Keycloak token exchange failed: ${errText}`);
					throw new Error(`Token exchange failed: ${tokenResponse.status} - ${errText}`);
				}

				const tokens = await tokenResponse.json();
				const keycloakAccessToken = tokens.access_token;
				const keycloakRefreshToken = tokens.refresh_token;
				const keycloakIdToken = tokens.id_token || '';

				if (!keycloakAccessToken) {
					throw new Error('No access_token returned by Keycloak');
				}

				logger.info(`👤 Fetching Keycloak user profile info...`);
				const userinfoUrl = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/userinfo`;
				const profileResponse = await fetch(userinfoUrl, {
					headers: { 'Authorization': `Bearer ${keycloakAccessToken}` }
				});

				if (!profileResponse.ok) {
					const errText = await profileResponse.text();
					logger.error(`❌ Keycloak userinfo request failed: ${errText}`);
					throw new Error(`Failed to get user profile from Keycloak: ${profileResponse.status}`);
				}

				const profile = await profileResponse.json();
				const email = profile.email;
				const sub = profile.sub;

				if (!email) {
					throw new Error('Keycloak profile did not contain an email address');
				}

				const { UsersService } = services;
				const schema = await getSchema();
				const usersService = new UsersService({ schema, knex: database });

				logger.info(`🔍 Finding or creating Directus user for email: ${email}`);
				let existingUsers = await usersService.readByQuery({
					filter: { email: { _eq: email } }
				});

				let user = existingUsers.length > 0 ? existingUsers[0] : null;

				if (!user) {
					logger.info(`✨ Creating new Directus user for: ${email}`);
					const userId = await usersService.createOne({
						email,
						first_name: profile.given_name || 'Keycloak',
						last_name: profile.family_name || 'User',
						role: DEFAULT_ROLE_ID,
						status: 'active',
						provider: 'keycloak',
						external_identifier: sub
					});
					user = await usersService.readOne(userId);
				} else {
					logger.info(`✅ Found existing Directus user for: ${email}`);
					if (user.provider !== 'keycloak' || user.external_identifier !== sub) {
						await usersService.updateOne(user.id, {
							provider: 'keycloak',
							external_identifier: sub
						});
					}
				}

				const payload = { id: user.id, role: user.role || DEFAULT_ROLE_ID, app_access: true, admin_access: false };
				const sessionToken = jwt.sign(payload, env.SECRET, { expiresIn: '7d', issuer: 'directus' });
				const refreshToken = jwt.sign({ id: user.id, type: 'refresh' }, env.SECRET, { expiresIn: '30d', issuer: 'directus' });

				let scheme = DEFAULT_SCHEME;
				let path = MOBILE_APP_CALLBACK_PATH;
				
				const rawCookie = req.cookies?.sso_mobile_redirect || 
					(req.headers.cookie?.split(';').map(c => c.trim()).find(c => c.startsWith('sso_mobile_redirect='))?.split('=')[1]);
					
				if (rawCookie) {
					try {
						const val = decodeURIComponent(rawCookie);
						const redirectInfo = JSON.parse(val);
						scheme = redirectInfo.scheme || scheme;
						path = redirectInfo.path || path;
					} catch (e) {
						logger.error('⚠️ Failed to parse sso_mobile_redirect cookie:', e);
					}
				}

				const keycloakCode = crypto.randomBytes(16).toString('hex');
				
				logger.info(`💾 Saving Keycloak tokens to temporary exchange table with code: ${keycloakCode}`);
				await database('sso_keycloak_tokens').insert({
					code: keycloakCode,
					access_token: keycloakAccessToken,
					refresh_token: keycloakRefreshToken || '',
					id_token: keycloakIdToken || ''
				});

				const redirectUrl = new URL(`${scheme}://${path.replace(/^\/+/, '')}`);
				redirectUrl.searchParams.set('access_token', sessionToken);
				redirectUrl.searchParams.set('refresh_token', refreshToken);
				redirectUrl.searchParams.set('expires', String(3600 * 24 * 7));
				redirectUrl.searchParams.set('user_id', user.id);
				redirectUrl.searchParams.set('email', email);
				redirectUrl.searchParams.set('keycloak_code', keycloakCode);

				res.clearCookie('sso_mobile_redirect', {
					httpOnly: true,
					secure: COOKIE_SECURE,
					sameSite: COOKIE_SAME_SITE,
					path: '/',
				});

				logger.info(`🚀 Keycloak login successful. Redirecting back to mobile app via 302: ${redirectUrl.toString()}`);
				return res.redirect(302, redirectUrl.toString());
			} catch (error) {
				logger.error('❌ Error in keycloak-callback:', error);
				
				const scheme = getValidatedScheme(req);
				const path = req.query.app_path || MOBILE_APP_CALLBACK_PATH;
				const errorRedirectUrl = `${scheme}://${path.replace(/^\/+/, '')}?error=INTERNAL_SERVER_ERROR&message=${encodeURIComponent(error.message)}`;

				res.setHeader('Content-Type', 'text/html');
				return res.status(500).send(renderFriendlyErrorPage(
					'Authentication Error',
					error.message || 'An unexpected error occurred during Keycloak callback exchange.',
					'INTERNAL_SERVER_ERROR',
					errorRedirectUrl
				));
			}
		});

		// Exchange short-lived code for Keycloak tokens
		router.get('/keycloak-token', async (req, res) => {
			const { code } = req.query;
			if (!code) {
				logger.error('❌ Keycloak Token exchange: Missing code parameter');
				return res.status(400).json({ error: 'Missing code' });
			}

			try {
				const row = await database('sso_keycloak_tokens')
					.where('code', code)
					.first();

				if (!row) {
					logger.error(`❌ Keycloak Token exchange: Code ${code} not found or expired`);
					return res.status(404).json({ error: 'Code not found or expired' });
				}

				await database('sso_keycloak_tokens')
					.where('code', code)
					.delete();

				try {
					const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
					await database('sso_keycloak_tokens')
						.where('created_at', '<', tenMinutesAgo)
						.delete();
				} catch (cleanupErr) {}

				logger.info(`✅ Keycloak tokens retrieved successfully for code: ${code}`);
				return res.json({
					success: true,
					access_token: row.access_token,
					refresh_token: row.refresh_token,
					id_token: row.id_token || ''
				});
			} catch (error) {
				logger.error('❌ Error exchanging Keycloak token code:', error);
				return res.status(500).json({ error: error.message });
			}
		});

		// Mobile callback endpoint
		router.get('/mobile-callback', async (req, res) => {
			const isBrowser = isBrowserRequest(req);
			const isBrowserForError = req.accepts('html') || req.headers.accept?.includes('text/html') || /Mozilla|Chrome|Safari|Firefox|Edge|Opera/i.test(req.headers['user-agent'] || '');
			try {
				let authResult = null;
				if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) authResult = await tryAllCookies(req, SESSION_COOKIE_NAME);
				if (!authResult) authResult = await tryAllCookies(req, CORE_COOKIE_NAME);
				if (!authResult) authResult = await tryEveryPossibleJwt(req);
				if (!authResult) authResult = await tryRefreshToken(req);

				if (!authResult) {
					if (isBrowserForError) {
						const scheme = getValidatedScheme(req);
						const path = req.query.app_path || MOBILE_APP_CALLBACK_PATH;
						const errorRedirectUrl = `${scheme}://${path.replace(/^\/+/, '')}?error=INVALID_CREDENTIALS&message=Authentication failed`;

						res.setHeader('Content-Type', 'text/html');
						return res.status(401).send(renderFriendlyErrorPage(
							'Authentication Failed',
							'Your login session is invalid or has expired. Please go back to the app and try logging in again.',
							'INVALID_CREDENTIALS',
							errorRedirectUrl
						));
					}
					return res.status(401).json({ error: 'Authentication failed' });
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

				logger.info(`🚀 Redirecting back to app via native 302: ${redirectUrl}`);
				return res.redirect(302, redirectUrl);
			} catch (error) {
				logger.error('Error in mobile-callback:', error);
				if (isBrowserForError) {
					const scheme = getValidatedScheme(req);
					const path = req.query.app_path || MOBILE_APP_CALLBACK_PATH;
					const errorRedirectUrl = `${scheme}://${path.replace(/^\/+/, '')}?error=INTERNAL_SERVER_ERROR&message=${encodeURIComponent(error.message)}`;

					res.setHeader('Content-Type', 'text/html');
					return res.status(500).send(renderFriendlyErrorPage(
						'Authentication Error',
						error.message || 'An unexpected error occurred during mobile authentication.',
						'INTERNAL_SERVER_ERROR',
						errorRedirectUrl
					));
				}
				res.status(500).json({ error: error.message });
			}
		});

		// Google callback endpoint
		router.get('/google-callback', async (req, res) => {
			const isBrowser = isBrowserRequest(req);
			const isBrowserForError = req.accepts('html') || req.headers.accept?.includes('text/html') || /Mozilla|Chrome|Safari|Firefox|Edge|Opera/i.test(req.headers['user-agent'] || '');
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
					if (isBrowserForError) {
						const scheme = getValidatedScheme(req);
						const path = req.query.app_path || GOOGLE_CALLBACK_PATH;
						const errorRedirectUrl = `${scheme}://${path.replace(/^\/+/, '')}?error=INVALID_CREDENTIALS&message=Authentication failed`;

						res.setHeader('Content-Type', 'text/html');
						return res.status(401).send(renderFriendlyErrorPage(
							'Authentication Failed',
							'Your Google login session is invalid or has expired. Please go back to the app and try logging in again.',
							'INVALID_CREDENTIALS',
							errorRedirectUrl
						));
					}
					return res.status(401).json({ error: 'Authentication failed' });
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
				logger.error('Error in google-callback:', error);
				if (isBrowserForError) {
					const scheme = getValidatedScheme(req);
					const path = req.query.app_path || GOOGLE_CALLBACK_PATH;
					const errorRedirectUrl = `${scheme}://${path.replace(/^\/+/, '')}?error=INTERNAL_SERVER_ERROR&message=${encodeURIComponent(error.message)}`;

					res.setHeader('Content-Type', 'text/html');
					return res.status(500).send(renderFriendlyErrorPage(
						'Authentication Error',
						error.message || 'An unexpected error occurred during Google authentication.',
						'INTERNAL_SERVER_ERROR',
						errorRedirectUrl
					));
				}
				res.status(500).json({ error: error.message });
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

			res.clearCookie(SESSION_COOKIE_NAME, cookieOptionsBase);
			if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
				res.clearCookie(CORE_COOKIE_NAME, cookieOptionsBase);
			}
			res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, cookieOptionsBase);

			if (COOKIE_DOMAIN) {
				const cookieOptionsWithDomain = { ...cookieOptionsBase, domain: COOKIE_DOMAIN };
				res.clearCookie(SESSION_COOKIE_NAME, cookieOptionsWithDomain);
				if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
					res.clearCookie(CORE_COOKIE_NAME, cookieOptionsWithDomain);
				}
				res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, cookieOptionsWithDomain);
			}

			try {
				res.clearCookie(SESSION_COOKIE_NAME, { ...cookieOptionsBase, domain: '.goyong.in' });
				res.clearCookie(CORE_COOKIE_NAME, { ...cookieOptionsBase, domain: '.goyong.in' });
				res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, { ...cookieOptionsBase, domain: '.goyong.in' });
			} catch (err) { }

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

				if (isKeycloakAdminConfigured && userEmail) {
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

				let directusLogoutOk = false;
				try {
					const logoutRes = await fetch(`${PUBLIC_URL}/auth/logout`, {
						method: 'POST',
						headers: {
							'Authorization': `Bearer ${token}`,
							'Content-Type': 'application/json',
						},
						body: JSON.stringify({}),
					});
					directusLogoutOk = logoutRes.ok || logoutRes.status === 204;
					logger.info(`[SSO] Directus /auth/logout → ${logoutRes.status} for user ${userId}`);
				} catch (logoutError) {
					logger.warn('[SSO] /auth/logout network error (non-fatal):', logoutError.message);
				}

				let deletedSessionsCount = 0;
				try {
					const decoded = jwt.decode(token);
					const sessionToken = decoded?.session;
					if (sessionToken) {
						const byToken = await database('directus_sessions')
							.where('token', sessionToken)
							.delete();
						deletedSessionsCount += byToken;
						logger.info(`[SSO] Deleted ${byToken} session(s) by token for user ${userId}`);
					}
					const byUser = await database('directus_sessions')
						.where('user', userId)
						.delete();
					deletedSessionsCount += byUser;
					if (byUser > 0) {
						logger.info(`[SSO] Deleted ${byUser} additional session(s) by user ID for ${userId}`);
					}
				} catch (sessionError) {
					logger.error('[SSO] Error deleting sessions:', sessionError);
				}

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
					external_identifier: null,
					provider: 'default',
				});

				logger.info(`[SSO] Soft-deleted user ${userId} → ${deletedEmail}, sessions cleared: ${deletedSessionsCount}, directus logout: ${directusLogoutOk}`);

				if (isKeycloakAdminConfigured) {
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
						logger.error('[SSO] Keycloak logout error:', keycloakError);
					}
				}

				const browserLogoutUrl = `${PUBLIC_URL}/sso/logout-clear`;

				return res.json({
					success: true,
					message: 'Account deleted successfully, sessions cleared.',
					sessions_cleared: deletedSessionsCount,
					browser_logout_url: browserLogoutUrl,
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

				let existingUsers = await usersService.readByQuery({
					filter: {
						_and: [
							{ external_identifier: { _eq: sub } },
							{ provider: { _eq: 'apple' } }
						]
					}
				});

				let user = existingUsers.length > 0 ? existingUsers[0] : null;

				if (!user) {
					existingUsers = await usersService.readByQuery({
						filter: { email: { _eq: email } }
					});

					if (existingUsers.length > 0) {
						user = existingUsers[0];
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

				const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
					headers: { 'Authorization': `Bearer ${token}` },
				});

				if (!meResponse.ok) return res.status(401).json({ error: 'Invalid token' });
				const userData = await meResponse.json();

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
			const isBrowserForError = req.accepts('html') || req.headers.accept?.includes('text/html') || /Mozilla|Chrome|Safari|Firefox|Edge|Opera/i.test(req.headers['user-agent'] || '');

			let userId = null;
			let finalToken = null;

			const scheme = getValidatedScheme(req);
			const path = req.query.app_path || MOBILE_APP_CALLBACK_PATH;
			const errorRedirectUrlBase = `${scheme}://${path.replace(/^\/+/, '')}`;

			if (bridge_token) {
				try {
					const decoded = jwt.verify(bridge_token, env.SECRET, { issuer: 'directus-sso' });
					if (decoded.purpose !== 'bridge') {
						if (isBrowserForError) {
							res.setHeader('Content-Type', 'text/html');
							return res.status(400).send(renderFriendlyErrorPage('Authentication Failed', 'Invalid token purpose.', 'INVALID_BRIDGE_TOKEN', `${errorRedirectUrlBase}?error=INVALID_BRIDGE_TOKEN&message=Invalid token purpose`));
						}
						return res.status(400).json({ error: 'Invalid token purpose' });
					}
					userId = decoded.sub;

					const payload = { id: userId, app_access: true, admin_access: false };
					finalToken = jwt.sign(payload, env.SECRET, { expiresIn: '7d', issuer: 'directus' });
				} catch (err) {
					if (isBrowserForError) {
						res.setHeader('Content-Type', 'text/html');
						return res.status(401).send(renderFriendlyErrorPage('Session Expired', 'Your secure login session has expired or is invalid. Please go back to the app and try logging in again.', 'EXPIRED_BRIDGE_TOKEN', `${errorRedirectUrlBase}?error=EXPIRED_BRIDGE_TOKEN&message=${encodeURIComponent(err.message)}`));
					}
					return res.status(401).json({ error: 'Invalid or expired bridge token', message: err.message });
				}
			} else if (token && ENABLE_LEGACY_BRIDGE) {
				logger.warn('⚠️ Warning: Legacy bridge token used. This flow is vulnerable to session fixation.');
				try {
					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
						headers: { 'Authorization': `Bearer ${token}` },
					});
					if (!meResponse.ok) {
						if (isBrowserForError) {
							res.setHeader('Content-Type', 'text/html');
							return res.status(401).send(renderFriendlyErrorPage('Session Expired', 'Your secure login session has expired or is invalid. Please go back to the app and try logging in again.', 'INVALID_CREDENTIALS', `${errorRedirectUrlBase}?error=INVALID_CREDENTIALS&message=Authentication failed`));
						}
						return res.status(401).json({ error: 'Invalid token' });
					}
					const userData = await meResponse.json();
					userId = userData.data.id;
					finalToken = token;
				} catch (err) {
					if (isBrowserForError) {
						res.setHeader('Content-Type', 'text/html');
						return res.status(500).send(renderFriendlyErrorPage('Authentication Error', 'An unexpected error occurred while bridging your session.', 'BRIDGE_FAILURE', `${errorRedirectUrlBase}?error=BRIDGE_FAILURE&message=${encodeURIComponent(err.message)}`));
					}
					return res.status(500).json({ error: 'Bridge failure', message: err.message });
				}
			} else {
				if (isBrowserForError) {
					res.setHeader('Content-Type', 'text/html');
					return res.status(400).send(renderFriendlyErrorPage('Authentication Failed', 'Secure bridge token is required to start your session.', 'MISSING_BRIDGE_TOKEN', `${errorRedirectUrlBase}?error=MISSING_BRIDGE_TOKEN&message=Secure bridge token required`));
				}
				return res.status(400).json({ error: 'Secure bridge token required' });
			}

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
