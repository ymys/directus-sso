
export function escapeHTML(str) {
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

export function renderFriendlyErrorPage(title, message, errorCode = 'AUTHENTICATION_FAILED', redirectUrl = null) {
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

export function getShared(env) {
	const rawSchemes = env.MOBILE_APP_SCHEME || 'finsnapp';
	const ALLOWED_SCHEMES = Array.isArray(rawSchemes)
		? rawSchemes.map(s => String(s).trim())
		: String(rawSchemes).split(',').map(s => s.trim());
	const DEFAULT_SCHEME = ALLOWED_SCHEMES[0];

	const MOBILE_APP_CALLBACK_PATH = env.MOBILE_APP_CALLBACK_PATH || '/auth/callback';
	const PUBLIC_URL = env.PUBLIC_URL || 'http://localhost:8055';
	const COOKIE_SECURE = env.COOKIE_SECURE !== 'false';
	const COOKIE_SAME_SITE = env.COOKIE_SAME_SITE || 'lax';
	const SESSION_COOKIE_NAME = env.SESSION_COOKIE_NAME || 'directus_session_token';
	const REFRESH_TOKEN_COOKIE_NAME = env.REFRESH_TOKEN_COOKIE_NAME || 'directus_refresh_token';
	const CORE_COOKIE_NAME = 'directus_session_token';
	const COOKIE_DOMAIN = env.COOKIE_DOMAIN || null;

	function getValidatedScheme(req) {
		let requestedScheme = req.query.app_scheme;

		if (!requestedScheme) {
			const redirectUri = req.query.redirect_uri || req.query.redirect;
			if (redirectUri && typeof redirectUri === 'string') {
				const match = redirectUri.match(/^([a-zA-Z0-9+-.]+):\/\//);
				if (match) {
					requestedScheme = match[1];
				}
			}
		}

		if (!requestedScheme && req.headers.cookie) {
			const cookies = req.headers.cookie.split(';').map(c => c.trim());
			const capturedCookie = cookies.find(c => c.startsWith('sso_captured_scheme='));
			if (capturedCookie) {
				requestedScheme = capturedCookie.split('=')[1];
			}
		}

		if (requestedScheme && ALLOWED_SCHEMES.includes(requestedScheme)) {
			return requestedScheme;
		}

		const safeLegacySchemes = ['portalpipq', 'portalpipq-dev', 'paramarthaapp', 'paramarthaapp-dev', 'finsnapp', 'portaldev'];
		if (requestedScheme && safeLegacySchemes.includes(requestedScheme)) {
			return requestedScheme;
		}

		return DEFAULT_SCHEME;
	}

	return {
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
	};
}
