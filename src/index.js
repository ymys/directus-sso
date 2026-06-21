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
		const KEYCLOAK_CLIENT_ID = env.KEYCLOAK_CLIENT_ID || env.AUTH_KEYCLOAK_CLIENT_ID || 'admin-cli';
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

		// Helper to render a beautiful user-friendly error page
		function renderFriendlyErrorPage(title, message, errorCode = 'AUTHENTICATION_FAILED', redirectUrl = null) {
			const escapedTitle = escapeHTML(title);
			const escapedMessage = escapeHTML(message);
			const escapedErrorCode = escapeHTML(errorCode);
			const jsRedirectUrl = JSON.stringify(redirectUrl || '');

			return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapedTitle}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            color: #1e293b;
        }
        .container {
            width: 100%;
            max-width: 440px;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.6);
            border-radius: 24px;
            padding: 40px 32px;
            box-shadow: 0 25px 50px -12px rgba(15, 23, 42, 0.08);
            text-align: center;
            animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .icon-wrapper {
            width: 72px;
            height: 72px;
            background: #fef2f2;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
            color: #ef4444;
            border: 1px solid #fee2e2;
            animation: scaleIn 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        @keyframes scaleIn {
            from { transform: scale(0); }
            to { transform: scale(1); }
        }
        .icon {
            width: 32px;
            height: 32px;
            fill: none;
            stroke: currentColor;
            stroke-width: 2.5;
            stroke-linecap: round;
            stroke-linejoin: round;
        }
        h1 {
            font-size: 24px;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 12px;
            letter-spacing: -0.02em;
        }
        p {
            font-size: 15px;
            line-height: 1.6;
            color: #64748b;
            margin-bottom: 32px;
        }
        .instruction-card {
            background: #f8fafc;
            border: 1px solid #f1f5f9;
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 28px;
            text-align: left;
        }
        .instruction-card h3 {
            font-size: 13px;
            font-weight: 700;
            color: #475569;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .instruction-list {
            list-style: none;
        }
        .instruction-list li {
            font-size: 14px;
            line-height: 1.5;
            color: #475569;
            margin-bottom: 10px;
            display: flex;
            align-items: flex-start;
        }
        .instruction-list li::before {
            content: "•";
            color: #ef4444;
            font-weight: bold;
            display: inline-block;
            width: 1em;
            margin-left: -0.2em;
            flex-shrink: 0;
        }
        .instruction-list li:last-child {
            margin-bottom: 0;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 14px 24px;
            background: #0f172a;
            color: #ffffff;
            border: none;
            border-radius: 16px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 6px -1px rgba(15, 23, 42, 0.1);
            text-decoration: none;
        }
        .btn:hover {
            background: #1e293b;
            transform: translateY(-1px);
            box-shadow: 0 10px 15px -3px rgba(15, 23, 42, 0.15);
        }
        .btn:active {
            transform: translateY(0);
        }
        .footer-text {
            font-size: 12px;
            color: #94a3b8;
            margin-top: 24px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon-wrapper">
            <svg class="icon" viewBox="0 0 24 24">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
        </div>
        <h1>${escapedTitle}</h1>
        <p>${escapedMessage}</p>
        
        <div class="instruction-card">
            <h3>How to resolve this</h3>
            <ul class="instruction-list">
                <li>Tap the <strong>✕</strong> close icon at the top left of this screen. Or simply close this page and try again.</li>
                <li>Click the back button or gesture.</li>
            </ul>
        </div>

        <button class="btn" id="returnBtn">Return to App</button>
        
        <div class="footer-text">
            Error Code: ${escapedErrorCode}
        </div>
    </div>

    <script>
        const redirectUrl = ${jsRedirectUrl};
        const returnBtn = document.getElementById('returnBtn');
        
        function handleReturn() {
            if (redirectUrl) {
                // Navigate via server-side 302 redirect to ensure SFSafariViewController / Chrome Custom Tabs intercept it and close
                window.location.href = "/sso/return?redirect_uri=" + encodeURIComponent(redirectUrl);
                
                // Fallback: try direct deep link and close window after 2.5 seconds if 302 redirect fails
                setTimeout(() => {
                    window.location.href = redirectUrl;
                    setTimeout(() => {
                        try { window.close(); } catch(e) {}
                    }, 1000);
                }, 2500);
            } else {
                try { window.close(); } catch(e) {}
            }
        }
        
        returnBtn.addEventListener('click', handleReturn);
        
        // Auto-redirect after 2 seconds if redirectUrl is available
        if (redirectUrl) {
            setTimeout(handleReturn, 2000);
        }
    </script>
</body>
</html>`;
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
			// 1. Try req.query.app_scheme
			let requestedScheme = req.query.app_scheme;

			// 2. Try parsing from req.query.redirect_uri or req.query.redirect
			if (!requestedScheme) {
				const redirectUri = req.query.redirect_uri || req.query.redirect;
				if (redirectUri && typeof redirectUri === 'string') {
					const match = redirectUri.match(/^([a-zA-Z0-9+-.]+):\/\//);
					if (match) {
						requestedScheme = match[1];
					}
				}
			}

			// 3. Try reading from raw req.headers.cookie manually in case cookie-parser hasn't executed
			if (!requestedScheme && req.headers.cookie) {
				const cookies = req.headers.cookie.split(';').map(c => c.trim());
				const capturedCookie = cookies.find(c => c.startsWith('sso_captured_scheme='));
				if (capturedCookie) {
					requestedScheme = capturedCookie.split('=')[1];
				}
			}

			if (requestedScheme && ALLOWED_SCHEMES.includes(requestedScheme)) {
				return requestedScheme;
			} else if (requestedScheme) {
				logger.warn(`⚠️ Warning: App requested scheme '${requestedScheme}', but it is not in .env. Falling back to '${DEFAULT_SCHEME}'`);
			}
			return DEFAULT_SCHEME;
		}

		// Global error/JSON interceptor to capture any 401 INVALID_CREDENTIALS or auth errors
		// returned by Directus core or external modules, and convert them to friendly HTML for browsers.
		let interceptorRegistered = false;
		function registerGlobalErrorInterceptor(app) {
			if (interceptorRegistered || app.__sso_error_interceptor_registered) return;
			app.__sso_error_interceptor_registered = true;
			interceptorRegistered = true;

			logger.info('🛠️ SSO global error interceptor registered on Express app');

			const errorInterceptor = (req, res, next) => {
				// Capture and store the app scheme if it's passed in the query during login initiation
				let schemeToCapture = req.query.app_scheme;
				if (!schemeToCapture) {
					const redirectUri = req.query.redirect_uri || req.query.redirect;
					if (redirectUri && typeof redirectUri === 'string') {
						const match = redirectUri.match(/^([a-zA-Z0-9+-.]+):\/\//);
						if (match) {
							schemeToCapture = match[1];
						}
					}
				}
				if (schemeToCapture && ALLOWED_SCHEMES.includes(schemeToCapture)) {
					// Store it in a secure cookie for 15 minutes to survive OAuth redirects
					res.cookie('sso_captured_scheme', schemeToCapture, {
						httpOnly: true,
						secure: COOKIE_SECURE,
						sameSite: COOKIE_SAME_SITE,
						maxAge: 15 * 60 * 1000, // 15 mins
						path: '/',
					});
				}

				const acceptsHtml = (typeof req.accepts === 'function' && req.accepts('html')) || req.headers.accept?.includes('text/html');
				const hasBrowserUA = /Mozilla|Chrome|Safari|Firefox|Edge|Opera/i.test(req.headers['user-agent'] || '');
				const isBrowser = acceptsHtml || hasBrowserUA;
				if (isBrowser) {
					// Override res.json to catch JSON error objects before they are sent
					const originalJson = res.json;
					res.json = function (body) {
						if (body && body.errors && Array.isArray(body.errors) && body.errors.length > 0) {
							const isInvalidCredentials = body.errors.some(e =>
								e.extensions?.code === 'INVALID_CREDENTIALS' ||
								e.message?.toLowerCase().includes('credentials')
							);

							if (isInvalidCredentials) {
								const scheme = getValidatedScheme(req);
								const path = req.query.app_path || MOBILE_APP_CALLBACK_PATH;
								const errorRedirectUrl = `${scheme}://${path.replace(/^\/+/, '')}?error=INVALID_CREDENTIALS&message=${encodeURIComponent(body.errors[0]?.message || '')}`;

								res.setHeader('Content-Type', 'text/html');

								// Clear all possible session cookies so the browser doesn't send them on next login attempts
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

								if (typeof res.status === 'function') res.status(401);
								return res.send(renderFriendlyErrorPage(
									'Login Session Expired',
									'Your login credentials are invalid or your session has expired. Please return to the app and try logging in again.',
									'INVALID_CREDENTIALS',
									errorRedirectUrl
								));
							}
						}
						return originalJson.apply(this, arguments);
					};
				}
				next();
			};

			// Let Express construct and register the Layer properly
			app.use(errorInterceptor);

			// Move it immediately after expressInit in the Express stack so req/res are fully decorated
			if (app._router && Array.isArray(app._router.stack)) {
				const lastLayer = app._router.stack.pop();
				if (lastLayer) {
					const initIndex = app._router.stack.findIndex(layer => layer.name === 'expressInit');
					if (initIndex !== -1) {
						// Insert immediately after expressInit
						app._router.stack.splice(initIndex + 1, 0, lastLayer);
						logger.info(`🛠️ SSO error interceptor moved immediately after expressInit (index ${initIndex + 1})`);
					} else {
						// Fallback: insert at index 1 or 2
						app._router.stack.splice(Math.min(2, app._router.stack.length), 0, lastLayer);
						logger.info(`🛠️ SSO error interceptor moved to index ${Math.min(2, app._router.stack.length)} (fallback)`);
					}
				}
			}
		}

		// Register on the first incoming request to the SSO extension
		router.use((req, res, next) => {
			if (req.app) {
				registerGlobalErrorInterceptor(req.app);
			}
			next();
		});

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
			
			// Store the app scheme and path in a cookie so we know where to redirect after callback
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

				if (!keycloakAccessToken) {
					throw new Error('No access_token returned by Keycloak');
				}

				// Fetch Keycloak user profile info
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

				// Find or create Directus user
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
					logger.info(`` + `✅ Found existing Directus user for: ${email}`);
					// Ensure external ID and provider are set correctly
					if (user.provider !== 'keycloak' || user.external_identifier !== sub) {
						await usersService.updateOne(user.id, {
							provider: 'keycloak',
							external_identifier: sub
						});
					}
				}

				// Generate Directus session tokens
				const payload = { id: user.id, role: user.role || DEFAULT_ROLE_ID, app_access: true, admin_access: false };
				const sessionToken = jwt.sign(payload, env.SECRET, { expiresIn: '7d', issuer: 'directus' });
				const refreshToken = jwt.sign({ id: user.id, type: 'refresh' }, env.SECRET, { expiresIn: '30d', issuer: 'directus' });

				// Get the stored redirect info from cookie
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

				// Construct redirect URL back to the mobile app with both Directus and Keycloak tokens
				const redirectUrl = new URL(`${scheme}://${path.replace(/^\/+/, '')}`);
				redirectUrl.searchParams.set('access_token', sessionToken);
				redirectUrl.searchParams.set('refresh_token', refreshToken);
				redirectUrl.searchParams.set('expires', String(3600 * 24 * 7));
				redirectUrl.searchParams.set('user_id', user.id);
				redirectUrl.searchParams.set('email', email);
				redirectUrl.searchParams.set('keycloak_access_token', keycloakAccessToken);
				if (keycloakRefreshToken) {
					redirectUrl.searchParams.set('keycloak_refresh_token', keycloakRefreshToken);
				}

				// Clear the redirect cookie
				res.clearCookie('sso_mobile_redirect', {
					httpOnly: true,
					secure: COOKIE_SECURE,
					sameSite: COOKIE_SAME_SITE,
					path: '/',
				});

				logger.info(`🚀 Keycloak login successful. Sending HTML deep-link redirect page...`);
				
				// We return HTTP 200 with an HTML landing page that triggers the redirect client-side.
				// This avoids "upstream sent too big header" (502 Bad Gateway) errors in Nginx caused by the large Keycloak JWT tokens in the Location header.
				res.setHeader('Content-Type', 'text/html');
				return res.status(200).send(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Redirecting...</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background-color: #f8fafc;
            margin: 0;
        }
        .card {
            background: white;
            padding: 32px;
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 360px;
        }
        h2 { color: #10b981; margin: 0 0 8px 0; }
        p { color: #64748b; margin: 0 0 24px 0; }
        .spinner {
            border: 3px solid #f1f5f9;
            border-top: 3px solid #10b981;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 24px auto;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background-color: #10b981;
            color: white !important;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="spinner"></div>
        <h2>Sinkronisasi Berhasil</h2>
        <p>Mengalihkan kembali ke aplikasi Paramartha...</p>
        <a href="${redirectUrl.toString()}" class="btn">Kembali ke Aplikasi</a>
    </div>
    <script>
        // Trigger redirect instantly
        window.location.replace("${redirectUrl.toString()}");
        
        // Fallback redirect on click
        document.querySelector('.btn').addEventListener('click', function() {
            window.location.href = "${redirectUrl.toString()}";
        });
    </script>
</body>
</html>
				`);
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

				res.setHeader('Location', redirectUrl);
				return res.status(302).send(`<html><head><meta http-equiv="refresh" content="0;url=${redirectUrl}"></head><body>Redirecting...</body></html>`);
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

				// 2. Call Directus /auth/logout FIRST — while the session is still active.
				//    This is important: if we delete from DB first, /auth/logout returns 401
				//    and can't clean up server-side state cleanly.
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

				// 3. Delete ALL remaining sessions for this user from the DB.
				//    We do this after /auth/logout so that logout can run cleanly,
				//    but we still purge everything to cover refresh tokens and other sessions.
				let deletedSessionsCount = 0;
				try {
					// 3a. Delete by the exact session token embedded in the JWT
					const decoded = jwt.decode(token);
					const sessionToken = decoded?.session;
					if (sessionToken) {
						const byToken = await database('directus_sessions')
							.where('token', sessionToken)
							.delete();
						deletedSessionsCount += byToken;
						logger.info(`[SSO] Deleted ${byToken} session(s) by token for user ${userId}`);
					}
					// 3b. Delete any other sessions (refresh tokens, concurrent sessions)
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

				// 4. Suspend + anonymise the user record
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
					// Clear the external_identifier so a new Google/Apple account
					// with the same email can re-register without conflicts.
					external_identifier: null,
					provider: 'default',
				});

				logger.info(`[SSO] Soft-deleted user ${userId} → ${deletedEmail}, sessions cleared: ${deletedSessionsCount}, directus logout: ${directusLogoutOk}`);

				// 5. Keycloak logout — ONLY if Keycloak is actually configured.
				//    We check env.KEYCLOAK_URL directly (not the local constant which has a fallback).
				//    If KEYCLOAK_URL is not in .env, env.KEYCLOAK_URL is undefined → falsy → skipped.
				//    NOTE: env.KEYCLOAK_ADMIN_USER === 'admin' is NOT a reliable signal —
				//    'admin' is the standard default Keycloak admin username for real setups.
				const isKeycloakConfigured = !!(
					env.KEYCLOAK_URL &&
					env.KEYCLOAK_REALM &&
					env.KEYCLOAK_ADMIN_USER &&
					env.KEYCLOAK_ADMIN_PASSWORD
				);

				if (isKeycloakConfigured) {
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

				// 6. Return a browser_logout_url that the mobile app MUST open in the browser.
				//    Rationale: Directus validates JWTs stateless-ly (signature + expiry only).
				//    Even after session DB deletion, the browser still has the old JWT cookie.
				//    Directus reads it, finds user=suspended, returns 401 INVALID_CREDENTIALS in ~3ms.
				//    The ONLY fix is to clear the browser cookie by navigating to logout-clear,
				//    which sets Set-Cookie: ...; Max-Age=0.
				const browserLogoutUrl = `${PUBLIC_URL}/sso/logout-clear`;

				return res.json({
					success: true,
					message: 'Account deleted successfully, sessions cleared.',
					sessions_cleared: deletedSessionsCount,
					// Mobile app must open this URL via WebBrowser to clear browser OAuth cookies
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
			const isBrowser = isBrowserRequest(req);
			const isBrowserForError = req.accepts('html') || req.headers.accept?.includes('text/html') || /Mozilla|Chrome|Safari|Firefox|Edge|Opera/i.test(req.headers['user-agent'] || '');

			let userId = null;
			let finalToken = null;

			// Generate deep link redirect URL on error
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

					// Generate a fresh session token for this user
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