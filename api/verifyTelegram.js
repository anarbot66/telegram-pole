// api/verifyTelegram.js
const crypto = require('crypto');
const admin = require('firebase-admin');

let adminInitialized = false;
function initFirebase() {
  if (adminInitialized) return;
  const b64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;
  if (!b64) throw new Error('FIREBASE_SERVICE_ACCOUNT_BASE64 not set');
  const sa = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
  admin.initializeApp({
    credential: admin.credential.cert(sa),
  });
  adminInitialized = true;
}

function verifyInitData(initData) {
  // initData — строка: window.Telegram.WebApp.initData (включает hash)
  const params = Object.fromEntries(new URLSearchParams(initData));
  const hash = params.hash;
  delete params.hash;

  // build data_check_string
  const dataCheckString = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join('\n');

  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) throw new Error('TELEGRAM_BOT_TOKEN not set');

  const secretKey = crypto.createHash('sha256').update(botToken).digest();
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  if (hmac !== hash) return null;
  return params;
}

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });
    const { initData } = req.body;
    if (!initData) return res.status(400).json({ error: 'initData required' });

    const verified = verifyInitData(initData);
    if (!verified) return res.status(403).json({ error: 'verification_failed' });

    // небольшая защита: проверим auth_date (чтобы не приняли старые initData)
    const authDate = parseInt(verified.auth_date || '0', 10);
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - authDate) > 300) { // 5 минут допустимо
      return res.status(403).json({ error: 'initData expired' });
    }

    initFirebase();

    // user может быть сериализован как JSON string
    let userObj = null;
    if (verified.user) {
      try {
        userObj = typeof verified.user === 'string' ? JSON.parse(verified.user) : verified.user;
      } catch (e) {
        userObj = verified.user;
      }
    }
    const tgId = userObj && userObj.id ? String(userObj.id) : null;
    if (!tgId) return res.status(400).json({ error: 'no_telegram_user' });

    // Создаём custom token с uid = telegram:<tgId>
    const firebaseUid = `telegram:${tgId}`;
    const customClaims = { isTelegram: true };

    const customToken = await admin.auth().createCustomToken(firebaseUid, customClaims);
    return res.json({ customToken, firebaseUid });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal_error' });
  }
};
