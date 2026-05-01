import crypto from 'node:crypto';

export async function getGoogleAccessToken(env) {
    const FCM_CLIENT_EMAIL = env.FCM_CLIENT_EMAIL;
    const FCM_PRIVATE_KEY = env.FCM_PRIVATE_KEY ? env.FCM_PRIVATE_KEY.replace(/\\n/g, '\n') : null;

    if (!FCM_CLIENT_EMAIL || !FCM_PRIVATE_KEY) {
        throw new Error('FCM_CLIENT_EMAIL or FCM_PRIVATE_KEY missing');
    }

    const header = { alg: 'RS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const claim = {
        iss: FCM_CLIENT_EMAIL,
        scope: 'https://www.googleapis.com/auth/firebase.messaging',
        aud: 'https://oauth2.googleapis.com/token',
        exp: now + 3600,
        iat: now
    };

    const encodeBase64Url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
    const signatureInput = `${encodeBase64Url(header)}.${encodeBase64Url(claim)}`;
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(signatureInput);
    const signature = sign.sign(FCM_PRIVATE_KEY, 'base64url');
    const jwt = `${signatureInput}.${signature}`;

    const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });

    if (!response.ok) throw new Error('Gagal mendapatkan token Google OAuth');
    const resData = await response.json();
    return resData.access_token;
}

export async function sendFCM(env, { tokens, title, body, metadata, logger }) {
    const FCM_PROJECT_ID = env.FCM_PROJECT_ID;
    
    if (!FCM_PROJECT_ID) throw new Error('FCM_PROJECT_ID missing');

    const accessToken = await getGoogleAccessToken(env);
    const results = [];

    for (const token of tokens) {
        const fcmPayload = {
            message: {
                token: token,
                notification: {
                    title: title || "Notifikasi Baru",
                    body: body || "Anda menerima pesan."
                },
                data: {
                    routing_info: metadata ? JSON.stringify(metadata) : "{}"
                }
            }
        };

        const sendResponse = await fetch(`https://fcm.googleapis.com/v1/projects/${FCM_PROJECT_ID}/messages:send`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(fcmPayload)
        });

        const sendResult = await sendResponse.json();
        results.push({ token, status: sendResponse.status, response: sendResult });
    }

    if (logger) {
        logger.info(`✅ FCM: Sent ${results.length} notifications.`);
    }
    
    return results;
}
