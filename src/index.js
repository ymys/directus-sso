export default {
	id: 'sso',
	handler: (router, { env, logger }) => {
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
		const CORE_COOKIE_NAME = 'directus_session_token'; // Core always uses this name internally

		logger.info('🚀 Mobile Auth Proxy Extension loaded');
		logger.info('🔐 Keycloak URL: ' + KEYCLOAK_URL);
		logger.info('🌐 Keycloak Realm: ' + KEYCLOAK_REALM);

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
			res.json({ status: 'ok', service: 'directus-mobile-auth-proxy' });
		});

		// Helper function to detect if request is from browser or mobile app
		function isBrowserRequest(req) {
			// Check explicit query parameter first
			if (req.query.type === 'browser') return true;
			if (req.query.type === 'mobile') return false;

			// Check User-Agent for common browser patterns
			const userAgent = req.headers['user-agent'] || '';
			const isBrowser = /Mozilla|Chrome|Safari|Firefox|Edge|Opera/i.test(userAgent) &&
				!/Mobile.*App|ReactNative|Expo/i.test(userAgent);

			return isBrowser;
		}



		// Mobile callback endpoint - handles OAuth redirect

		// old: jalan Mobile callback endpoint - handles OAuth redirect
		// Mobile callback endpoint - handles OAuth redirect
		router.get('/mobile-callback', async (req, res) => {
			const isBrowser = isBrowserRequest(req); // FIXED 1: Define isBrowser
			logger.info(`${isBrowser ? '🌐' : '📱'} ${isBrowser ? 'Browser' : 'Mobile'} callback received`);
			logger.info('Cookies: ' + JSON.stringify(req.cookies));
			logger.info('Query: ' + JSON.stringify(req.query));

			try {
				// Fallback mechanism: Try to read core cookie if instance cookie is missing
				let sessionToken = req.cookies[SESSION_COOKIE_NAME];
				if (!sessionToken && SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
					sessionToken = req.cookies[CORE_COOKIE_NAME];
					if (sessionToken) {
						logger.info(`🔄 Bridging core token to ${SESSION_COOKIE_NAME}`);
					}
				}

				if (!sessionToken) {
					logger.error('❌ No session token found in cookies');
					return res.send(`
			<html>
				<body>
					<h2>Authentication Failed</h2>
					<p>No session token found. Please try logging in again.</p>
					<a href="${PUBLIC_URL}/auth/login/keycloak">Try Again</a>
				</body>
			</html>
		`);
				}

				logger.info('✅ Session token found, length: ' + sessionToken.length);

				// Get user info using the session token – ALWAYS use CORE_COOKIE_NAME internally
				const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
					headers: {
						'Cookie': `${CORE_COOKIE_NAME}=${sessionToken}`,
					},
				});

				if (!meResponse.ok) {
					throw new Error('Failed to get user info: ' + await meResponse.text());
				}

				const userData = await meResponse.json();
				const userId = userData.data.id;
				const userEmail = userData.data.email;

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
				// E.g., portalpipq://auth/callback?access_token=...
				// Note: Ensure your MOBILE_APP_CALLBACK_PATH starts with an extra slash if you want two slashes! 
				// If MOBILE_APP_CALLBACK_PATH is "/auth/callback", this builds "portalpipq:/auth/callback" which React Native handles strictly like a real URI path.
				const redirectPath = MOBILE_APP_CALLBACK_PATH.startsWith('/') ? MOBILE_APP_CALLBACK_PATH : `//${MOBILE_APP_CALLBACK_PATH}`;
				const redirectUrl = `${MOBILE_APP_SCHEME}:${redirectPath}?access_token=${accessToken}&user_id=${userId}&email=${encodeURIComponent(userEmail || '')}`;

				logger.info('🔄 Redirecting to app: ' + redirectUrl);

				// Use HTTP redirect for mobile apps
				res.redirect(redirectUrl);

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
				// Fallback mechanism: Try to read core cookie if instance cookie is missing
				let sessionToken = req.cookies[SESSION_COOKIE_NAME];
				if (!sessionToken && SESSION_COOKIE_NAME !== CORE_COOKIE_NAME) {
					sessionToken = req.cookies[CORE_COOKIE_NAME];
					if (sessionToken) {
						logger.info(`🔄 Bridging core token to ${SESSION_COOKIE_NAME} (Google)`);
					}
				}

				if (!sessionToken) {
					logger.error('❌ No session token found in cookies (Google)');
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
									a { display: inline-block; margin-top: 20px; padding: 10px 20px; 
									    background: #4285f4; color: white; text-decoration: none; border-radius: 4px; }
									a:hover { background: #357ae8; }
								</style>
							</head>
							<body>
								<div class="container">
									<h2>Authentication Failed</h2>
									<p>No session token found. Please close this and try logging in again.</p>
								</div>
							</body>
						</html>
					`);
				}

				logger.info('✅ Session token found (Google), length: ' + sessionToken.length);

				// Get user info using the session token – ALWAYS use CORE_COOKIE_NAME internally
				const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
					headers: {
						'Cookie': `${CORE_COOKIE_NAME}=${sessionToken}`,
					},
				});

				if (!meResponse.ok) {
					throw new Error('Failed to get user info: ' + await meResponse.text());
				}

				const userData = await meResponse.json();
				const userId = userData.data.id;
				const userEmail = userData.data.email;
				const userName = userData.data.first_name || userData.data.email;

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

				// Build redirect URL with token for Google callback
				const redirectUrl = new URL(`${MOBILE_APP_SCHEME}://${GOOGLE_CALLBACK_PATH}`);
				redirectUrl.searchParams.set('access_token', accessToken);
				redirectUrl.searchParams.set('user_id', userId);
				redirectUrl.searchParams.set('email', userEmail || '');
				redirectUrl.searchParams.set('provider', 'google');

				logger.info('🔄 Redirecting to app (Google): ' + redirectUrl.toString());

				// Use HTTP redirect for mobile apps
				res.redirect(redirectUrl.toString());

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

		// WebView SSO Bridge - Establishes browser session from mobile token


	}
};
