require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit'); // YENİ EKLENDİ

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

// --- RATE LIMITING (Brute Force Koruması) ---
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 5, // 15 dakikada en fazla 5 deneme
    message: { error: 'Çok fazla giriş denemesi yaptınız. Lütfen 15 dakika sonra tekrar deneyin.' }
});

const users = [{ id: 1, username: 'taha', password: 'password123', role: 'admin' }];
const SECRET_KEY = process.env.JWT_SECRET || 'gizli_anahtar';

// --- AUDIT LOGS (Güvenlik Seyir Defteri) ---
const auditLogs = [];
const addLog = (event, user, device, status) => {
    auditLogs.unshift({ time: new Date().toLocaleTimeString(), event, user, device, status });
    if (auditLogs.length > 20) auditLogs.pop(); // Son 20 logu tut
};

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
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '2h' });

    res.cookie('auth_token', token, {
        httpOnly: true, secure: false, sameSite: 'Strict', maxAge: 2 * 60 * 60 * 1000
    });

    addLog('Login Success', username, clientFingerprint, '✅ BAŞARILI');
    res.json({ message: 'Giriş Başarılı! Token cihaza mühürlendi.' });
});

// --- GUARD MIDDLEWARE ---
const verifyDeviceFingerprint = (req, res, next) => {
    const token = req.cookies.auth_token;
    const currentFingerprint = req.headers['x-device-fingerprint'];

    if (!token) return res.status(401).json({ error: 'Erişim Reddedildi: Token yok.' });
    if (!currentFingerprint) return res.status(400).json({ error: 'Cihaz kimliği eksik.' });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        
        if (decoded.deviceId !== currentFingerprint) {
            addLog('Session Hijack Attempt', decoded.id, currentFingerprint, '❌ ENGELLENDİ');
            return res.status(403).json({ error: 'Session Hijacking Tespit Edildi! Erişim Kesildi.' });
        }

        req.user = decoded; 
        next(); 
    } catch (error) {
        res.status(403).json({ error: 'Geçersiz Token.' });
    }
};

// --- KORUMALI DASHBOARD (LOGLARI GÖSTERİR) ---
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