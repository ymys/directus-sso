# Mobile Auth Proxy - Directus Extension

This extension allows you to use the web and mobile OAuth callback and logout endpoints directly through your Directus domain.

## Installation

1. **Build the extension:**
   ```bash
   cd extensions/endpoints/mobile-auth-proxy
   npm install
   npm run build
   ```

2. **The extension will be automatically loaded by Directus** when you restart it.

## Endpoints

Once installed, the following endpoints will be available on your Directus domain:

- **Health Check:** `GET /mobile-auth-proxy/health`
- **Mobile/Browser Callback (Keycloak):** `GET /mobile-auth-proxy/mobile-callback`
- **Mobile/Browser Callback (Google):** `GET /mobile-auth-proxy/google-callback`
- **Mobile Logout:** `POST /mobile-auth-proxy/mobile-logout`

## Configuration

The extension uses environment variables from your Directus configuration:

# Add these to your Directus .env file
KEYCLOAK_URL=http://keycloak:8080
KEYCLOAK_REALM=testing
KEYCLOAK_CLIENT_ID=admin-cli
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD=admin
PUBLIC_URL=http://localhost:8055
MOBILE_APP_SCHEME=portalpipq
MOBILE_APP_CALLBACK_PATH=/auth/callback
GOOGLE_CALLBACK_PATH=/auth/callback/google
COOKIE_DOMAIN=.your-domain.com
COOKIE_SECURE=true
COOKIE_SAME_SITE=lax
```

### Security Note

Ensure specific values like `KEYCLOAK_Admin_PASSWORD` are kept secure and not committed to version control. The extension now uses environment variables for all sensitive configuration.

## Usage

### Browser Authentication Flow

The extension now supports **both browser and mobile app authentication** with automatic detection. After successful Keycloak login:

- **Browser requests**: Session is saved with cookies, allowing SSO across multiple services
- **Mobile app requests**: Access token is returned via deep link as before

#### Browser Login Example:

**For Keycloak:**
```javascript
// Simply navigate to the login URL
window.location.href = 'http://your-directus-domain.com/auth/login/keycloak';

// Or with a custom redirect after login
window.location.href = 'http://your-directus-domain.com/auth/login/keycloak?redirect_uri=/dashboard';
```

**For Google:**
```javascript
// Simply navigate to the Google login URL
window.location.href = 'http://your-directus-domain.com/auth/login/google';

// Or with a custom redirect after login
window.location.href = 'http://your-directus-domain.com/auth/login/google?redirect_uri=/dashboard';
```

After successful login, the user will see a success page and the session cookie will be saved. The user can then access other URLs using the same SSO without logging in again.

#### Forcing Browser Mode:

If auto-detection doesn't work correctly, you can force browser mode:

```javascript
window.location.href = 'http://your-directus-domain.com/auth/login/keycloak?type=browser';
```

#### Query Parameters:

- `type`: Force `browser` or `mobile` mode (optional, auto-detected if not provided)
- `redirect_uri` or `redirect`: URL to redirect to after successful login (optional, defaults to `/admin`)

### Mobile App Authentication Flow

Update your mobile app to use the new Directus domain URLs:

### Before (separate proxy server):
```javascript
const PROXY_URL = 'http://your-proxy-domain.com:3000';
const callbackUrl = `${PROXY_URL}/mobile-callback`;
```

### After (Directus extension):
```javascript
const DIRECTUS_URL = 'http://your-directus-domain.com';
const callbackUrl = `${DIRECTUS_URL}/mobile-auth-proxy/mobile-callback`;
```

### Login Flow:
```javascript
import * as WebBrowser from 'expo-web-browser';

const result = await WebBrowser.openAuthSessionAsync(
  `${DIRECTUS_URL}/auth/login/keycloak`,
  'myapp://auth/callback'
);
```

### Logout:
```javascript
const response = await fetch(`${DIRECTUS_URL}/mobile-auth-proxy/mobile-logout`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
  },
});
```

## Advantages Over Standalone Proxy

1. **Single Domain:** No need to deploy a separate server
2. **Unified Management:** Managed alongside your Directus instance
3. **Same Environment:** Uses Directus environment variables and configuration
4. **Built-in Logging:** Uses Directus logger for consistent logging
5. **Easier Deployment:** Deployed automatically with Directus

## Development

To make changes and test locally:

```bash
cd extensions/endpoints/mobile-auth-proxy
npm run dev
```

This will watch for changes and rebuild automatically.

## Keycloak Client Configuration

Update your Keycloak client's redirect URI to use the Directus domain:

**Valid Redirect URIs:**
```
http://your-directus-domain.com/auth/login/keycloak/callback
http://your-directus-domain.com/mobile-auth-proxy/mobile-callback
myapp://auth/callback
```

**Web Origins:**
```
http://your-directus-domain.com
```

## Notes

- The extension requires Directus 11.0.0 or higher
- Make sure cookie-parser middleware is available (Directus includes this by default)
- The extension has access to the same network as Directus, so internal service URLs (like `http://keycloak:8080`) will work if using Docker
