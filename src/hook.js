import { getShared } from './shared.js';

export default ({ init }, context) => {
	const { env, logger } = context;
	const {
		ALLOWED_SCHEMES,
		DEFAULT_SCHEME,
		PUBLIC_URL,
		COOKIE_SECURE,
		COOKIE_SAME_SITE,
		SESSION_COOKIE_NAME,
		CORE_COOKIE_NAME,
		COOKIE_DOMAIN,
		REFRESH_TOKEN_COOKIE_NAME,
		getValidatedScheme,
		renderFriendlyErrorPage
	} = getShared(env);

	logger.info('🛠️ SSO Hook Initialized: Registering global error and legacy login interceptor...');

	init('middlewares.before', ({ app }) => {
		app.use((req, res, next) => {
			// 1. Intercept legacy mobile requests targeting Directus's native `/auth/login/keycloak`
			// and redirect them to our custom proxy login flow, which handles user linking safely.
			if (req.method === 'GET' && req.path === '/auth/login/keycloak') {
				const redirectParam = req.query.redirect_uri || req.query.redirect;
				if (redirectParam && typeof redirectParam === 'string' && redirectParam.includes('sso/mobile-callback')) {
					logger.info(`📱 Intercepted legacy /auth/login/keycloak request. Redirecting to OIDC proxy flow...`);
					const targetUrl = new URL(`${PUBLIC_URL}/sso/login/keycloak`);
					targetUrl.searchParams.set('app_scheme', DEFAULT_SCHEME);
					targetUrl.searchParams.set('app_path', '/auth/callback');
					return res.redirect(targetUrl.toString());
				}
			}

			// 2. Capture and store the app scheme if it's passed in the query during login initiation
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
				res.cookie('sso_captured_scheme', schemeToCapture, {
					httpOnly: true,
					secure: COOKIE_SECURE,
					sameSite: COOKIE_SAME_SITE,
					maxAge: 15 * 60 * 1000, // 15 mins
					path: '/',
				});
			}

			// 3. Global error/JSON interceptor to capture any 401 INVALID_CREDENTIALS or auth errors
			const acceptsHtml = (typeof req.accepts === 'function' && req.accepts('html')) || req.headers.accept?.includes('text/html');
			const hasBrowserUA = /Mozilla|Chrome|Safari|Firefox|Edge|Opera/i.test(req.headers['user-agent'] || '');
			const isBrowser = acceptsHtml || hasBrowserUA;
			if (isBrowser) {
				const originalJson = res.json;
				res.json = function (body) {
					if (body && body.errors && Array.isArray(body.errors) && body.errors.length > 0) {
						const isInvalidCredentials = body.errors.some(e =>
							e.extensions?.code === 'INVALID_CREDENTIALS' ||
							e.message?.toLowerCase().includes('credentials')
						);

						if (isInvalidCredentials) {
							const scheme = getValidatedScheme(req);
							const path = req.query.app_path || '/auth/callback';
							const errorRedirectUrl = `${scheme}://${path.replace(/^\/+/, '')}?error=INVALID_CREDENTIALS&message=${encodeURIComponent(body.errors[0]?.message || '')}`;

							res.setHeader('Content-Type', 'text/html');

							// Clear all possible session cookies
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
		});
	});
};
