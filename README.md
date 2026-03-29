# Directus SSO - Mobile & Web OAuth Proxy

This extension provides optimized OAuth callback and logout endpoints for Directus, supporting both **Mobile App Deep Linking** and **Web Browser SSO** (Single Sign-On) with automatic detection.

## 🚀 Features

- **Unified Callbacks**: Handle both Keycloak and Google OAuth redirects in one place.
- **Smart Detection**: Automatically detects if the request comes from a mobile app or a web browser.
- **Resilient Authentication**:
  - **Cookie Brute-Force**: Tries multiple session cookies to handle domain conflicts.
  - **Mega Brute-Force**: Scans all cookies for valid JWT tokens if named lookups fail.
  - **Refresh Fallback**: Automatically attempts to use refresh tokens if the session is expired.
- **Dynamic Deep Linking**: Support for multi-tenant mobile apps via `app_scheme` and `app_path` parameters.
- **Seamless Logout**: Terminate both Directus and Keycloak sessions simultaneously.

## 📦 Installation

1. **Copy to extensions folder:**
   Ensure this project is in your Directus `extensions/endpoints/sso` directory.

2. **Install dependencies & build:**
   ```bash
   npm install
   npm run build
   ```

3. **Restart Directus**: The extension will be loaded automatically.

## 🔌 Endpoints

- **Health Check:** `GET /sso/health`
- **Keycloak Callback:** `GET /sso/mobile-callback`
- **Google Callback:** `GET /sso/google-callback`
- **Logout Proxy:** `POST /sso/mobile-logout`

## ⚙️ Configuration

Add these variables to your Directus `.env` file:

```env
# Directus Public URL
PUBLIC_URL=https://directus.example.com

# Keycloak Configuration
KEYCLOAK_URL=https://keycloak.example.com
KEYCLOAK_REALM=production
KEYCLOAK_CLIENT_ID=admin-cli
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD=your-password

# Mobile App Defaults
MOBILE_APP_SCHEME=myapp
MOBILE_APP_CALLBACK_PATH=/auth/callback
GOOGLE_CALLBACK_PATH=/auth/callback/google

# Web SSO Settings
COOKIE_DOMAIN=.example.com
COOKIE_SECURE=true
COOKIE_SAME_SITE=lax
SESSION_COOKIE_NAME=directus_session_token
REFRESH_TOKEN_COOKIE_NAME=directus_refresh_token
DEFAULT_ROLE_ID=your-default-role-uuid
```

### 🍎 Apple Authentication Note

Unlike Google (which uses Directus's native settings), the **Apple Native Token Flow** (`/apple-token`) manages user creation within this extension. You **must** provide a `DEFAULT_ROLE_ID` in your environment variables to ensure new Apple users are assigned the correct permissions.

## 📱 Mobile Usage

In your mobile app (e.g., React Native / Expo), point your OAuth login to Directus but use the proxy callbacks:

### 1. Keycloak Flow
```javascript
const loginUrl = `${DIRECTUS_URL}/auth/login/keycloak?redirect_uri=${DIRECTUS_URL}/sso/mobile-callback`;
```

### 2. Google Flow
```javascript
const loginUrl = `${DIRECTUS_URL}/auth/login/google?redirect_uri=${DIRECTUS_URL}/sso/google-callback`;
```

### 3. Dynamic App Redirection
If you have multiple apps or environments, you can override the scheme/path:
```javascript
const loginUrl = `${DIRECTUS_URL}/auth/login/google?redirect_uri=${DIRECTUS_URL}/sso/google-callback&app_scheme=alternateapp&app_path=/custom/callback`;
```

## 🌐 Web SSO Usage

For browser-based apps, simply navigate to the login endpoints. The extension will set the appropriate cookies and redirect the user:

```javascript
// Navigates to Directus login, then redirects back to your dashboard with session cookies set
window.location.href = `${DIRECTUS_URL}/auth/login/keycloak?redirect_uri=https://dashboard.example.com`;
```

## 🔐 Security Note

This extension facilitates session bridging. Ensure `COOKIE_SECURE=true` is used in production and `COOKIE_DOMAIN` is correctly scoped to your parent domain (e.g., `.example.com`) to enable SSO between subdomains.

---
Built with ❤️ for Directus.
