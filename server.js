require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

const users = [{ id: 1, username: 'taha', password: 'password123', role: 'admin' }];
const SECRET_KEY = process.env.JWT_SECRET;

// --- GİRİŞ (LOGIN) ENDPOINT'İ ---
app.post('/api/login', (req, res) => {
    const { username, password, clientFingerprint } = req.body;
    const user = users.find(u => u.username === username && u.password === password);

    if (!user) return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı!' });
    if (!clientFingerprint) return res.status(400).json({ error: 'Güvenlik İhlali: Cihaz Parmak İzi bulunamadı!' });

    const payload = { id: user.id, role: user.role, deviceId: clientFingerprint };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '2h' });

    res.cookie('auth_token', token, {
        httpOnly: true,
        secure: false, // Localhost için false
        sameSite: 'Strict',
        maxAge: 2 * 60 * 60 * 1000
    });

    res.json({ message: 'Giriş Başarılı! Token güvenli bir şekilde cihaza mühürlendi.' });
});

// --- GUARD MIDDLEWARE (KAPI GÖREVLİSİ) ---
// Bu fonksiyon, korumalı sayfalara girmeden önce çalışır ve Session Hijacking'i engeller.
const verifyDeviceFingerprint = (req, res, next) => {
    const token = req.cookies.auth_token;
    const currentFingerprint = req.headers['x-device-fingerprint']; // İstemcinin şu anki cihaz kimliği

    if (!token) {
        return res.status(401).json({ error: 'Erişim Reddedildi: Token bulunamadı.' });
    }

    if (!currentFingerprint) {
        return res.status(400).json({ error: 'Güvenlik İhlali: İstek başlığında cihaz kimliği eksik.' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        
        // ASIL GÜVENLİK KONTROLÜ (Token'daki mühür ile şu anki cihaz aynı mı?)
        if (decoded.deviceId !== currentFingerprint) {
            console.log(`🚨 SALDIRI GİRİŞİMİ TESPİT EDİLDİ! Orijinal Cihaz: ${decoded.deviceId}, Gelen Cihaz: ${currentFingerprint}`);
            return res.status(403).json({ 
                error: 'Session Hijacking Tespit Edildi! Token başka bir cihazda kullanılmaya çalışılıyor.' 
            });
        }

        req.user = decoded; // Kontrol başarılıysa kullanıcı bilgisini geç
        next(); // Korumalı sayfaya izin ver
    } catch (error) {
        res.status(403).json({ error: 'Geçersiz veya süresi dolmuş Token.' });
    }
};

// --- KORUMALI ENDPOINT (DASHBOARD) ---
// Sadece Guard'dan geçenler bu veriyi görebilir.
app.get('/api/dashboard', verifyDeviceFingerprint, (req, res) => {
    res.json({ 
        message: 'Gizli Bilgilere Eriştiniz!', 
        user: req.user,
        info: 'Sadece cihaz parmak izi eşleşen kullanıcılar burayı görebilir.'
    });
});

app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🛡️ Güvenli API Ayakta: http://localhost:${PORT}`);
});