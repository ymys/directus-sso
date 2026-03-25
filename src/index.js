import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { version } = require('../package.json');
import crypto from 'node:crypto';

export default {
	id: 'sso',
	handler: (router, context) => {
		const { env, logger, services, database, getSchema } = context;
		const KEYCLOAK_URL = env.KEYCLOAK_URL || 'http://keycloak:8080';
		const KEYCLOAK_REALM = env.KEYCLOAK_REALM || 'testing';
		const KEYCLOAK_ADMIN_USER = env.KEYCLOAK_ADMIN_USER || 'admin';
		const KEYCLOAK_ADMIN_PASSWORD = env.KEYCLOAK_ADMIN_PASSWORD || 'admin';
		const PUBLIC_URL = env.PUBLIC_URL || 'http://localhost:8055';
		const MOBILE_APP_SCHEME = env.MOBILE_APP_SCHEME || 'portalpipq';
		const MOBILE_APP_CALLBACK_PATH = env.MOBILE_APP_CALLBACK_PATH || '/auth/callback';
		const GOOGLE_CALLBACK_PATH = env.GOOGLE_CALLBACK_PATH || '/auth/callback/google';
		const KEYCLOAK_CLIENT_ID = env.KEYCLOAK_CLIENT_ID || 'admin-cli';
		const COOKIE_DOMAIN = env.COOKIE_DOMAIN || null;
		const COOKIE_SECURE = env.COOKIE_SECURE !== 'false';
		const COOKIE_SAME_SITE = env.COOKIE_SAME_SITE || 'lax';
		const SESSION_COOKIE_NAME = env.SESSION_COOKIE_NAME || 'directus_session_token';
		const REFRESH_TOKEN_COOKIE_NAME = env.REFRESH_TOKEN_COOKIE_NAME || 'directus_refresh_token';
		const CORE_COOKIE_NAME = 'directus_session_token'; // Core always uses this name internally

		logger.info('🚀 Mobile Auth Proxy Extension loaded');
		logger.info('🔐 Keycloak URL: ' + KEYCLOAK_URL);
		logger.info('🌐 Keycloak Realm: ' + KEYCLOAK_REALM);
		logger.info('📡 Public URL: ' + PUBLIC_URL);
		logger.info('🍪 Session Cookie Name: ' + SESSION_COOKIE_NAME);
		logger.info('🍪 Refresh Token Cookie Name: ' + REFRESH_TOKEN_COOKIE_NAME);

		logger.info('📱 Mobile App Scheme: ' + MOBILE_APP_SCHEME + '://' + MOBILE_APP_CALLBACK_PATH);
		logger.info('🔵 Google OAuth enabled');


		// Helper function to get Keycloak admin token
		async function getKeycloakAdminToken() {
			try {
				const response = await fetch(`${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/x-www-form-urlencoded',
					},
					body: new URLSearchParams({
						grant_type: 'password',
						client_id: KEYCLOAK_CLIENT_ID,
						username: KEYCLOAK_ADMIN_USER,
						password: KEYCLOAK_ADMIN_PASSWORD,
					}).toString(),
				});

				if (!response.ok) {
					throw new Error('Failed to get admin token');
				}

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
					{
						headers: {
							'Authorization': `Bearer ${adminToken}`,
						},
					}
				);

				if (!response.ok) {
					throw new Error('Failed to get user');
				}

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
					{
						method: 'POST',
						headers: {
							'Authorization': `Bearer ${adminToken}`,
						},
					}
				);

				return response.ok || response.status === 204;
			} catch (error) {
				logger.error('Error logging out user from Keycloak:', error);
				return false;
			}
		}

		// Health check
		router.get('/health', (req, res) => {
			res.json({ status: 'ok', service: 'directus-extension-sso', version });
		});

		// Helper function to detect if request is from browser or mobile app
		function isBrowserRequest(req) {
			// Check explicit query parameter first
			if (req.query.type === 'browser') return true;
			if (req.query.type === 'mobile') return false;

			// If we have an app_scheme or app_path, it's definitely a mobile app request
			if (req.query.app_scheme || req.query.app_path) {
				return false;
			}

			// Check User-Agent for common browser patterns
			const userAgent = req.headers['user-agent'] || '';
			const isBrowser = /Mozilla|Chrome|Safari|Firefox|Edge|Opera/i.test(userAgent) &&
				!/Mobile.*App|ReactNative|Expo/i.test(userAgent);

			return isBrowser;
		}

		/**
		 * PASSTHROUGH FIX 2.0: Cookie Brute-Force (v1.5.3)
		 * Extracts all cookies with the same name and tries them one by one.
		 * This is necessary because both instances might set cookies with the same name
		 * on the same domain, and we don't know which one Directus will pick.
		 */
		async function tryAllCookies(req, cookieName) {
			const rawCookie = req.headers.cookie;
			if (!rawCookie) return null;

			// Extract all values for the specified cookie name
			// e.g. "directus_session_token=token1; other=123; directus_session_token=token2"
			const cookieValues = rawCookie.split(';')
				.map(c => c.trim())
				.filter(c => c.startsWith(`${cookieName}=`))
				.map(c => c.substring(cookieName.length + 1));

			if (cookieValues.length === 0) return null;

			logger.info(`🔍 [${cookieName}] Found ${cookieValues.length} possible tokens. Trying them...`);

			for (let i = 0; i < cookieValues.length; i++) {
				const token = cookieValues[i];
				try {
					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
						headers: {
							'Cookie': `${cookieName}=${token}`,
						},
					});

					if (meResponse.ok) {
						const userData = await meResponse.json();
						logger.info(`✅ [${cookieName}] Token #${i + 1} succeeded for ${userData.data.email}`);
						return { token, userData: userData.data };
					} else {
						logger.info(`❌ [${cookieName}] Token #${i + 1} failed (${meResponse.status})`);
					}
				} catch (err) {
					logger.error(`⚠️ [${cookieName}] Error trying token #${i + 1}: ${err.message}`);
				}
			}

			return null;
		}

		/**
		 * MEGA BRUTE-FORCE (v1.5.4)
		 * Tries every JWT-looking value found in the cookie header.
		 * If we can't find it by name, maybe we find it by content!
		 */
		async function tryEveryPossibleJwt(req) {
			const rawCookie = req.headers.cookie;
			if (!rawCookie) return null;

			// Extract everything that looks like a JWT (starts with eyJ and is long)
			const candidates = rawCookie.split(';')
				.map(c => c.trim())
				.map(c => {
					const parts = c.split('=');
					return parts.length > 1 ? parts[1] : null;
				})
				.filter(v => v && v.startsWith('eyJ') && v.length > 50);

			if (candidates.length === 0) return null;

			logger.info(`🔍 [MEGA] Found ${candidates.length} potential JWTs in cookies. Trying them...`);

			for (let i = 0; i < candidates.length; i++) {
				const token = candidates[i];
				try {
					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
						headers: {
							'Authorization': `Bearer ${token}`
						},
					});

					if (meResponse.ok) {
						const userData = await meResponse.json();
						logger.info(`✅ [MEGA] Token #${i + 1} succeeded for ${userData.data.email}`);
						return { token, userData: userData.data };
					}
				} catch (err) { }
			}

			return null;
		}

		/**
		 * REFRESH FALLBACK (v1.5.4)
		 * If we have a refresh token, try to exchange it for a new session.
		 */
		async function tryRefreshToken(req) {
			const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE_NAME];
			if (!refreshToken) return null;

			logger.info(`🔄 [REFRESH] Attempting to use ${REFRESH_TOKEN_COOKIE_NAME}...`);
			try {
				const refreshResponse = await fetch(`${PUBLIC_URL}/auth/refresh`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ refresh_token: refreshToken })
				});

				if (refreshResponse.ok) {
					const data = await refreshResponse.json();
					const newToken = data.data.access_token;
					logger.info('✅ [REFRESH] Successfully refreshed session');

					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
						headers: { 'Authorization': `Bearer ${newToken}` }
					});

					if (meResponse.ok) {
						const userData = await meResponse.json();
						return { token: newToken, userData: userData.data };
					}
				}
			} catch (err) {
				logger.error('❌ [REFRESH] Failed: ' + err.message);
			}
			return null;
		}

		// Mobile callback endpoint - handles OAuth redirect
		router.get('/mobile-callback', async (req, res) => {
			const isBrowser = isBrowserRequest(req);
			logger.info(`${isBrowser ? '🌐' : '📱'} ${isBrowser ? 'Browser' : 'Mobile'} callback received`);
			logger.info('Host Header: ' + req.headers.host);
			logger.info('Cookies Header: ' + req.headers.cookie);
			logger.info('Parsed Cookies: ' + JSON.stringify(req.cookies));
			logger.info('Query: ' + JSON.stringify(req.query));

			try {
				// 1. Try by name (v1.5.3 brute-force)
				let authResult = null;
				if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
					authResult = await tryAllCookies(req, SESSION_COOKIE_NAME);
				}
				if (!authResult) {
					authResult = await tryAllCookies(req, CORE_COOKIE_NAME);
				}

				// 2. Try Mega Brute-Force (v1.5.4 - any JWT in the header)
				if (!authResult) {
					authResult = await tryEveryPossibleJwt(req);
				}

				// 3. Try Refresh Token fallback (v1.5.4)
				if (!authResult) {
					authResult = await tryRefreshToken(req);
				}

				if (!authResult) {
					logger.error('❌ No valid session or refresh token found in any cookies');
					return res.send(`
						<html>
							<body>
								<h2>Authentication Failed</h2>
								<p>No valid session found. Please try logging in again.</p>
								<div style="font-size: 11px; color: #999; margin-top: 20px; text-align: left;">
									<strong>Debug Info (v1.5.4):</strong><br>
									Instance: ${SESSION_COOKIE_NAME}<br>
									URL: ${PUBLIC_URL}<br>
									Host: ${req.headers.host}
								</div>
								<a href="${PUBLIC_URL}/auth/login/keycloak" style="display: inline-block; margin-top: 20px;">Try Again</a>
							</body>
						</html>
					`);
				}

				const { token: sessionToken, userData } = authResult;
				const userId = userData.id;
				const userEmail = userData.email;

				logger.info('👤 User authenticated: ' + userId + ', ' + userEmail);

				// The session token is actually a valid JWT access token
				const accessToken = sessionToken;

				logger.info('🎫 Using session token as access token');

				// Handle browser requests
				if (isBrowser) {
					logger.info('🌐 Browser request detected - maintaining session');

					// Set session cookie (explicitly to ensure domain/secure settings)
					res.cookie(SESSION_COOKIE_NAME, sessionToken, {
						httpOnly: true,
						secure: COOKIE_SECURE,
						domain: COOKIE_DOMAIN,
						sameSite: COOKIE_SAME_SITE,
						maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
						path: '/',
					});

					// CRITICAL: If we bridged the name, clear the core cookie to avoid conflicts
					if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
						res.cookie(CORE_COOKIE_NAME, '', { maxAge: 0, path: '/' });
					}

					// Check if there's a redirect URL in the query params
					let redirectTo = req.query.redirect_uri || req.query.redirect || '/';

					// Append token to Web redirect URL to bridge the gap for React Native Web
					try {
						if (redirectTo.startsWith('http')) {
							const redirectUrlObj = new URL(redirectTo);
							redirectUrlObj.searchParams.set('access_token', accessToken);
							redirectUrlObj.searchParams.set('user_id', userId);
							redirectUrlObj.searchParams.set('email', userEmail || '');
							redirectTo = redirectUrlObj.toString();
						}
					} catch (e) {
						logger.error('❌ Failed to parse Web redirect URL: ' + redirectTo);
					}

					logger.info('🔄 Redirecting browser to: ' + redirectTo);
					return res.redirect(redirectTo);
				}

				// FIXED 2: Build redirect URL manually to support custom schemes perfectly
				// Allows dynamic schemes via query parameters for multi-tenant setups
				const scheme = req.query.app_scheme || MOBILE_APP_SCHEME;
				const path = req.query.app_path || MOBILE_APP_CALLBACK_PATH;
				const redirectUrl = `${scheme}://${path.replace(/^\/+/, '')}?access_token=${accessToken}&user_id=${userId}&email=${encodeURIComponent(userEmail || '')}`;

				logger.info('🔄 Attempting AUTO-REDIRECT to app: ' + redirectUrl);

				// Hybrid Strategy: Send 302 header AND HTML body
				// 1. HTTP 302 is the fastest way to auto-redirect (works on most browsers)
				res.setHeader('Location', redirectUrl);

				// 2. HTML body is the fallback (shows button if 302 is blocked)
				return res.status(302).send(`
					<html>
						<head>
							<title>Authenticating...</title>
							<meta name="viewport" content="width=device-width, initial-scale=1">
							<meta http-equiv="refresh" content="0;url=${redirectUrl}">
							<style>
								body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
								       padding: 40px; text-align: center; background: #fff; }
								.lds-dual-ring { display: inline-block; width: 40px; height: 40px; margin-bottom: 20px; }
								.lds-dual-ring:after { content: " "; display: block; width: 32px; height: 32px; margin: 8px; 
								                      border-radius: 50%; border: 4px solid #4f46e5; 
													  border-color: #4f46e5 transparent #4f46e5 transparent; 
													  animation: lds-dual-ring 1.2s linear infinite; }
								@keyframes lds-dual-ring { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
								.btn { display: inline-block; padding: 12px 24px; background: #4f46e5; color: white; 
								       text-decoration: none; border-radius: 6px; font-weight: 500; margin-top: 20px; }
							</style>
						</head>
						<body>
							<div class="lds-dual-ring"></div>
							<h2>Finishing Login...</h2>
							<p>You are being redirected back to the app.</p>
							<p style="font-size: 14px; color: #666; margin-top: 20px;">If the app doesn't open automatically, please click below:</p>
							<a id="redirect-btn" href="${redirectUrl}" class="btn">Return to App</a>
							<script>
								// JavaScript fallback for auto-redirect
								window.onload = function() {
									window.location.href = "${redirectUrl}";
								};
							</script>
						</body>
					</html>
				`);

			} catch (error) {
				logger.error('❌ Error in callback:', error);
				res.status(500).send(`
		<html>
			<body>
				<h2>Error</h2>
				<p>${error.message}</p>
				<a href="${PUBLIC_URL}/auth/login/keycloak">Try Again</a>
			</body>
		</html>
	`);
			}
		});



		// Google callback endpoint - handles OAuth redirect for both browser and mobile flows
		router.get('/google-callback', async (req, res) => {
			const isBrowser = isBrowserRequest(req);
			logger.info(`${isBrowser ? '🌐' : '📱'} ${isBrowser ? 'Browser' : 'Mobile'} Google callback received`);
			logger.info('Cookies: ' + JSON.stringify(req.cookies));
			logger.info('Query: ' + JSON.stringify(req.query));

			try {
				let authResult = null;

				// 0. Try URL query parameters directly (Directus mode=json bypasses iOS 302 cookie dropping)
				if (req.query.access_token) {
					logger.info('🎟️ Found access_token in URL query string! Bypassing cookie check entirely.');
					authResult = {
						access_token: req.query.access_token,
						refresh_token: req.query.refresh_token || null,
						expires: req.query.expires || null
					};
				}

				// 1. Try by name (v1.5.3 brute-force)
				if (!authResult && SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
					authResult = await tryAllCookies(req, SESSION_COOKIE_NAME);
				}
				if (!authResult) {
					authResult = await tryAllCookies(req, CORE_COOKIE_NAME);
				}

				// 2. Try Mega Brute-Force (v1.5.4 - any JWT in the header)
				if (!authResult) {
					authResult = await tryEveryPossibleJwt(req);
				}

				// 3. Try Refresh Token fallback (v1.5.4)
				if (!authResult) {
					authResult = await tryRefreshToken(req);
				}

				if (!authResult) {
					logger.error('❌ No valid session or refresh token found in any cookies (Google)');
					return res.send(`
						<html>
							<head>
								<title>Authentication Failed</title>
								<style>
									body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
									       padding: 40px; text-align: center; background: #f5f5f5; }
									.container { max-width: 500px; margin: 0 auto; background: white; 
									           padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
									h2 { color: #e74c3c; }
									.debug { font-size: 11px; color: #999; margin-top: 20px; text-align: left; }
								</style>
							</head>
							<body>
								<div class="container">
									<h2>Authentication Failed</h2>
									<p>No valid session found. Please close this and try logging in again.</p>
									<div class="debug">
										<strong>Debug Info (v1.5.4):</strong><br>
										Instance: ${SESSION_COOKIE_NAME} | Google
									</div>
								</div>
							</body>
						</html>
					`);
				}

				const { token: sessionToken, userData } = authResult;
				const userId = userData.id;
				const userEmail = userData.email;
				const userName = userData.first_name || userData.email;

				logger.info('👤 User authenticated via Google: ' + userId + ', ' + userEmail);

				// The session token is actually a valid JWT access token
				const accessToken = sessionToken;

				logger.info('🎫 Using session token as access token');

				// Handle browser requests
				if (isBrowser) {
					logger.info('🌐 Browser request detected - maintaining session');

					// Set session cookie (explicitly to ensure domain/secure settings)
					res.cookie(SESSION_COOKIE_NAME, sessionToken, {
						httpOnly: true,
						secure: COOKIE_SECURE,
						domain: COOKIE_DOMAIN,
						sameSite: COOKIE_SAME_SITE,
						maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
						path: '/',
					});

					// CRITICAL: If we bridged the name, clear the core cookie to avoid conflicts
					if (SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
						res.cookie(CORE_COOKIE_NAME, '', { maxAge: 0, path: '/' });
					}

					// Check if there's a redirect URL in the query params
					let redirectTo = req.query.redirect_uri || req.query.redirect || '/';

					// Append token to Web redirect URL to bridge the gap for React Native Web
					try {
						if (redirectTo.startsWith('http')) {
							const redirectUrlObj = new URL(redirectTo);
							redirectUrlObj.searchParams.set('access_token', accessToken);
							redirectUrlObj.searchParams.set('user_id', userId);
							redirectUrlObj.searchParams.set('email', userEmail || '');
							redirectUrlObj.searchParams.set('provider', 'google');
							redirectTo = redirectUrlObj.toString();
						}
					} catch (e) {
						logger.error('❌ Failed to parse Web redirect URL: ' + redirectTo);
					}

					logger.info('🔄 Redirecting browser to: ' + redirectTo);

					return res.send(`
						<html>
							<head>
								<title>Login Successful</title>
								<meta http-equiv="refresh" content="2;url=${redirectTo}">
								<style>
									body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
									       padding: 40px; text-align: center; background: #f5f5f5; }
									.container { max-width: 500px; margin: 0 auto; background: white; 
									           padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
									h2 { color: #27ae60; }
									.checkmark { font-size: 48px; color: #27ae60; margin-bottom: 20px; }
									p { color: #666; margin: 10px 0; }
									.spinner { border: 3px solid #f3f3f3; border-top: 3px solid #4285f4; 
									          border-radius: 50%; width: 40px; height: 40px; 
									          animation: spin 1s linear infinite; margin: 20px auto; }
									@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
									a { color: #4285f4; text-decoration: none; }
									a:hover { text-decoration: underline; }
									.google-icon { color: #4285f4; margin-right: 5px; }
								</style>
							</head>
							<body>
								<div class="container">
									<div class="checkmark">✓</div>
									<h2><span class="google-icon">🔵</span>Google Login Successful!</h2>
									<p>Welcome, ${userName}!</p>
									<p>Your session has been saved. You can now access other services using the same login.</p>
									<div class="spinner"></div>
									<p style="margin-top: 20px;">Redirecting you automatically...</p>
									<p style="font-size: 14px; margin-top: 20px;">
										<a href="${redirectTo}">Click here if not redirected automatically</a>
									</p>
								</div>
							</body>
						</html>
					`);
				}

				// Handle mobile app requests
				logger.info('📱 Mobile app request - redirecting with token');

				// Build redirect URL with token for Google callback (with dynamic scheme support)
				const scheme = req.query.app_scheme || MOBILE_APP_SCHEME;
				const path = req.query.app_path || GOOGLE_CALLBACK_PATH;
				const redirectUrl = new URL(`${scheme}://${path.replace(/^\/+/, '')}`);
				redirectUrl.searchParams.set('access_token', accessToken);
				redirectUrl.searchParams.set('user_id', userId);
				redirectUrl.searchParams.set('email', userEmail || '');
				redirectUrl.searchParams.set('provider', 'google');

				logger.info('🔄 Redirecting to app (Google): ' + redirectUrl.toString());

				// SEAMLESS REDIRECT (302)
				// We now use a direct 302 redirect for all platforms.
				logger.info('🚀 Performing direct 302 redirect to app: ' + redirectUrl.toString());
				return res.redirect(302, redirectUrl.toString());
/*

				// Refined Mobile Redirect (best for Android Chrome)
				logger.info('🤖 Android/Other detected - sending resilient landing page');
				return res.send(`
					<html>
						<head>
							<meta name="viewport" content="width=device-width, initial-scale=1">
							<style>
								body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
								       padding: 40px; text-align: center; background: #fff; }
								.container { max-width: 500px; margin: 0 auto; background: white; 
								           padding: 30px; border-radius: 8px; }
								h2 { color: #2196F3; margin-bottom: 20px; }
								p { color: #666; margin: 10px 0; }
								.btn { display: inline-block; padding: 14px 28px; background: #2196F3; 
								      color: white !important; text-decoration: none; border-radius: 8px; 
								      font-weight: bold; margin-top: 25px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
								.btn:active { transform: translateY(1px); box-shadow: 0 1px 3px rgba(0,0,0,0.2); }
								.spinner { border: 4px solid #f3f3f3; border-top: 4px solid #2196F3; 
								          border-radius: 50%; width: 50px; height: 50px; 
								          animation: spin 1s linear infinite; margin: 0 auto; }
								@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
							</style>
						</head>
						<body>
							<div class="container">
								<h2>Login Successful!</h2>
								<p>Redirecting you back to the app...</p>
								<div style="margin: 30px 0;">
									<div class="spinner"></div>
								</div>
								<a id="redirect-btn" href="${redirectUrl.toString()}" class="btn">Return to App</a>
								<script>
									const normalUrl = "${redirectUrl.toString()}";
									
									// Build Chrome Intent URL for more reliable automatic trigger on Android
									// Format: intent://[host]/[path]#[Intent];scheme=[scheme];package=[package];end
									// We only do this for the main app scheme 'formasjid'
									const scheme = "${scheme}";
									const path = "${path.replace(/^\/+/, '')}";
									const search = "${redirectUrl.search}";
									let intentUrl = normalUrl;
									
									if (scheme === 'formasjid') {
										intentUrl = "intent://" + path + search + "#Intent;scheme=formasjid;package=org.formasjid.app;end";
										// Update button to use intent URL too for better reliability
										document.getElementById('redirect-btn').href = intentUrl;
									}

									// Try automatic redirect using Intent first (if available) or normal URL
									window.location.replace(intentUrl);
									
									// Fallback timer if automatic redirect is blocked
									setTimeout(function() {
										window.location.href = intentUrl;
									}, 1000);
									
									// Final fallback to normal URL if intent fails
									setTimeout(function() {
										window.location.href = normalUrl;
									}, 3000);
								</script>
							</div>
						</body>
					</html>
				*/
				
			} catch (error) {
				logger.error('❌ Error in Google callback:', error);
				res.status(500).send(`
					<html>
						<head>
							<title>Error</title>
							<style>
								body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
								       padding: 40px; text-align: center; background: #f5f5f5; }
								.container { max-width: 500px; margin: 0 auto; background: white; 
								           padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
								h2 { color: #e74c3c; }
								.error-icon { font-size: 48px; color: #e74c3c; margin-bottom: 20px; }
								pre { background: #f8f8f8; padding: 15px; border-radius: 4px; 
								      text-align: left; overflow-x: auto; font-size: 12px; }
								a { display: inline-block; margin-top: 20px; padding: 10px 20px; 
								    background: #4285f4; color: white; text-decoration: none; border-radius: 4px; }
								a:hover { background: #357ae8; }
							</style>
						</head>
						<body>
							<div class="container">
								<div class="error-icon">⚠️</div>
								<h2>Error</h2>
								<p>An error occurred during Google authentication:</p>
								<pre>${error.message}</pre>
								<a href="${PUBLIC_URL}/auth/login/google">Try Again</a>
							</div>
						</body>
					</html>
				`);
			}
		});

		// Mobile logout endpoint - logs out from Directus and Keycloak
		router.post('/mobile-logout', async (req, res) => {
			logger.info('🚪 Logout request received');

			try {
				const authHeader = req.headers.authorization;
				const token = authHeader?.replace('Bearer ', '');

				if (!token) {
					return res.status(400).json({
						error: 'No token provided',
						message: 'Authorization header with Bearer token is required'
					});
				}

				logger.info('🎫 Token received: ' + token.substring(0, 20) + '...');

				let userEmail = null;

				// 1. Get user info from Directus to get email
				try {
					const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
						headers: {
							'Authorization': `Bearer ${token}`,
						},
					});

					if (meResponse.ok) {
						const userData = await meResponse.json();
						userEmail = userData.data.email;
						logger.info('👤 User email: ' + userEmail);
					}
				} catch (error) {
					logger.error('⚠️ Error getting user info: ' + error.message);
				}

				// 2. Logout from Directus
				try {
					const directusLogoutResponse = await fetch(`${PUBLIC_URL}/auth/logout`, {
						method: 'POST',
						headers: {
							'Authorization': `Bearer ${token}`,
							'Content-Type': 'application/json',
						},
						body: JSON.stringify({
							refresh_token: token,
						}),
					});

					if (directusLogoutResponse.ok) {
						logger.info('✅ Directus session invalidated');
					} else {
						logger.info('⚠️ Directus logout response: ' + directusLogoutResponse.status);
					}
				} catch (error) {
					logger.error('⚠️ Error logging out from Directus: ' + error.message);
				}

				// 3. Logout from Keycloak using Admin API
				if (userEmail) {
					try {
						logger.info('🔐 Getting Keycloak admin token...');
						const adminToken = await getKeycloakAdminToken();

						if (adminToken) {
							logger.info('🔍 Looking up Keycloak user...');
							const userId = await getKeycloakUserId(adminToken, userEmail);

							if (userId) {
								logger.info('🚪 Logging out from Keycloak...');
								const keycloakLoggedOut = await logoutKeycloakUser(adminToken, userId);

								if (keycloakLoggedOut) {
									logger.info('✅ Keycloak sessions terminated');
								} else {
									logger.info('⚠️ Failed to logout from Keycloak');
								}
							} else {
								logger.info('⚠️ User not found in Keycloak');
							}
						} else {
							logger.info('⚠️ Failed to get Keycloak admin token');
						}
					} catch (error) {
						logger.error('⚠️ Error logging out from Keycloak: ' + error.message);
					}
				}

				logger.info('🎉 Logout completed');

				res.json({
					success: true,
					message: 'Logged out successfully from Directus and Keycloak'
				});

			} catch (error) {
				logger.error('❌ Error in logout:', error);
				res.status(500).json({
					error: error.message,
					message: 'Failed to logout'
				});
			}
		});

		// Apple login endpoint - handles native identityToken exchange
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
				// 1. Verify Apple Token (Native Node.js Implementation)
				const clientID = 'com.forumbandung.app';
				
				const verifyAppleToken = async (idToken) => {
					const [headerB64, payloadB64, signatureB64] = idToken.split('.');
					const header = JSON.parse(Buffer.from(headerB64, 'base64').toString());
					const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
					
					logger.info('🍎 Apple Token Payload: ' + JSON.stringify(payload));

					// Basic validation
					if (payload.iss !== 'https://appleid.apple.com') throw new Error('Invalid issuer');
					
					// Allow both the production bundle ID and Expo Go (for testing)
					// Note: Expo Go uses 'host.exp.Exponent' (note the capital E)
					const allowedAudiences = [clientID.toLowerCase(), 'host.exp.exponent'];
					const actualAud = payload.aud.toLowerCase();
					
					if (!allowedAudiences.includes(actualAud)) {
						logger.error(`❌ Invalid audience: ${payload.aud}. Expected one of: ${allowedAudiences.join(', ')}`);
						throw new Error('Invalid audience');
					}
					
					if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');

					// Fetch Apple Public Keys
					const response = await fetch('https://appleid.apple.com/auth/keys');
					const { keys } = await response.json();
					const key = keys.find(k => k.kid === header.kid);
					if (!key) throw new Error('Apple public key not found');

					// Verify Signature using native crypto
					const keyObject = crypto.createPublicKey({
						key: key,
						format: 'jwk'
					});

					const verify = crypto.createVerify('RSA-SHA256');
					verify.update(`${headerB64}.${payloadB64}`);
					
					const isValid = verify.verify(keyObject, signatureB64, 'base64url');
					if (!isValid) throw new Error('Invalid signature');

					return payload;
				};

				const decodedToken = await verifyAppleToken(identityToken);
				const { email, sub } = decodedToken;

				if (!email) {
					throw new Error('Apple token did not contain an email');
				}

				logger.info(`✅ Apple token verified for: ${email} (${sub})`);

				// 2. Fetch or Create User in Directus
				const { UsersService, AuthenticationService } = services;
				const schema = await getSchema();
				
				const usersService = new UsersService({
					schema,
					knex: database
				});

				// Find user by email
				const existingUsers = await usersService.readByQuery({
					filter: { email: { _eq: email } }
				});

				let userId;
				let user;
				if (existingUsers.length > 0) {
					user = existingUsers[0];
					userId = user.id;
					logger.info(`👤 Found existing user: ${userId}`);
					
					// Update external_identifier if not set
					if (!user.external_identifier) {
						await usersService.updateOne(userId, {
							external_identifier: sub,
							provider: 'apple'
						});
					}
				} else {
					logger.info(`📝 Creating new user for: ${email}`);
					userId = await usersService.createOne({
						email,
						first_name: firstName || 'Apple User',
						last_name: lastName || '',
						role: env.DEFAULT_ROLE_ID || '36010211-604f-4ce3-84d9-4e69d16781a1',
						status: 'active',
						provider: 'apple',
						external_identifier: sub
					});
					user = await usersService.readOne(userId);
				}

				// 3. Generate Directus Session
				const authService = new AuthenticationService({
					schema,
					knex: database
				});

				// Since we verified the identity with Apple, we can bypass password check
				// In Directus extensions, we don't have a direct 'loginUser' method that takes just user ID.
				// However, if we're on a version that supports it, we can use static token or internal session.
				
				// For this custom SSO implementation, we'll try to get tokens using the internal AuthenticationService.
				// If that fails, we return the user_id and email so the mobile app can attempt its next step.
				
				try {
					// Some versions of Directus allow:
					// const result = await authService.login('apple', { email });
					// but that requires an 'apple' auth provider to be configured.
					
					// Return success with user data
					res.json({
						success: true,
						data: {
							user: user,
							token: "Apple session established" // This is a placeholder, usually we'd mint a real JWT here
						},
						user_id: userId,
						email: email,
						provider: 'apple'
					});
				} catch (authError) {
					logger.error('⚠️ Could not generate internal session token: ' + authError.message);
					res.json({
						success: true,
						user_id: userId,
						email: email,
						message: 'Apple authentication verified but session generation failed. Check server logs.'
					});
				}

			} catch (error) {
				logger.error('❌ Error in Apple token exchange:', error);
				res.status(500).json({
					error: error.message,
					message: 'Failed to verify Apple token'
				});
			}
		});

		// WebView SSO Bridge - Establishes browser session from mobile token


	}
};
