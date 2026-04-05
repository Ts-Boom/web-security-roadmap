require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

// --- RATE LIMITING ---
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Çok fazla deneme. Lütfen 15 dakika bekleyin.' }
});

const users = [{ id: 1, username: 'taha', password: 'password123', role: 'admin' }];
const SECRET_KEY = process.env.JWT_SECRET || 'gizli_anahtar';

// --- AUDIT LOGS ---
const auditLogs = [];
const addLog = (event, user, device, status) => {
    auditLogs.unshift({ time: new Date().toLocaleTimeString(), event, user, device, status });
    if (auditLogs.length > 20) auditLogs.pop();
};

// --- TOKEN BLACKLIST (KARA LİSTE) ---
// İptal edilen (Revoke) token'ların tutulduğu liste (Gerçekte Redis kullanılır)
const revokedTokens = new Set(); 

// --- GİRİŞ (LOGIN) ENDPOINT'İ ---
app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password, clientFingerprint } = req.body;
    const user = users.find(u => u.username === username && u.password === password);

    if (!user) {
        addLog('Login Attempt', username, clientFingerprint || 'Bilinmiyor', '🚨 BAŞARISIZ');
        return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı!' });
    }

    if (!clientFingerprint) return res.status(400).json({ error: 'Cihaz Parmak İzi bulunamadı!' });

    const payload = { id: user.id, role: user.role, deviceId: clientFingerprint };
    // Token'a benzersiz bir kimlik (jti) ekliyoruz ki spesifik token'ı iptal edebilelim
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '2h', jwtid: Date.now().toString() });

    res.cookie('auth_token', token, {
        httpOnly: true, secure: false, sameSite: 'Strict', maxAge: 2 * 60 * 60 * 1000
    });

    addLog('Login Success', username, clientFingerprint, '✅ BAŞARILI');
    res.json({ message: 'Giriş Başarılı! Token cihaza mühürlendi.' });
});

// --- ÇIKIŞ VE TOKEN İPTALİ (LOGOUT / REVOKE) ENDPOINT'İ ---
app.post('/api/logout', (req, res) => {
    const token = req.cookies.auth_token;
    
    if (token) {
        // Token'ı Kara Listeye ekle (Revoke işlemi)
        revokedTokens.add(token);
        
        try {
           const decoded = jwt.decode(token);
           if(decoded) addLog('Logout/Revoke', decoded.id, decoded.deviceId, '🔒 İPTAL EDİLDİ');
        } catch(e) {}
    }

    // Cookie'yi tarayıcıdan temizle
    res.clearCookie('auth_token');
    res.json({ message: 'Güvenli Çıkış Yapıldı. Oturum İptal Edildi (Revoked).' });
});

// --- GUARD MIDDLEWARE ---
const verifyDeviceFingerprint = (req, res, next) => {
    const token = req.cookies.auth_token;
    const currentFingerprint = req.headers['x-device-fingerprint'];

    if (!token) return res.status(401).json({ error: 'Erişim Reddedildi: Token yok.' });
    if (!currentFingerprint) return res.status(400).json({ error: 'Cihaz kimliği eksik.' });

    // 1. KONTROL: Token Kara Listede mi? (Revoked Check)
    if (revokedTokens.has(token)) {
        addLog('Revoked Access Attempt', 'Unknown', currentFingerprint, '⛔ KARA LİSTE');
        return res.status(401).json({ error: 'Bu oturum iptal edilmiş (Revoked)! Lütfen tekrar giriş yapın.' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        
        // 2. KONTROL: Cihaz Parmak İzi Eşleşiyor mu? (Session Hijacking Check)
        if (decoded.deviceId !== currentFingerprint) {
            addLog('Session Hijack Attempt', decoded.id, currentFingerprint, '❌ ENGELLENDİ');
            // Şüpheli bir durumda bu token'ı otomatik olarak iptal edebiliriz (Opsiyonel Güvenlik Önlemi)
            // revokedTokens.add(token); 
            return res.status(403).json({ error: 'Session Hijacking Tespit Edildi! Erişim Kesildi.' });
        }

        req.user = decoded; 
        next(); 
    } catch (error) {
        res.status(403).json({ error: 'Geçersiz veya Süresi Dolmuş Token.' });
    }
};

// --- KORUMALI DASHBOARD ---
app.get('/api/dashboard', verifyDeviceFingerprint, (req, res) => {
    res.json({ 
        message: 'Güvenli Alana Hoş Geldiniz, Yönetici.', 
        logs: auditLogs 
    });
});

app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🛡️ Güvenli API Ayakta: http://localhost:${PORT}`);
});