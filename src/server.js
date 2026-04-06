const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const SECRET_KEY = 'legendary-secops-key-2026';

// 1. Giriş ve Cihaz Parmak İzi Kaydı
app.post('/api/login', (req, res) => {
    const { username, fingerprint } = req.body;

    if (!fingerprint) {
        return res.status(400).json({ error: 'Cihaz Parmak İzi (Fingerprint) zorunludur!' });
    }

    // Token oluşturulurken cihazın parmak izi içine mühürleniyor (Binding)
    const token = jwt.sign({ username, fingerprint }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token, message: 'Giriş başarılı, oturum cihaza kilitlendi.' });
});

// 2. Korumalı Rota ve Hijacking Kontrolü
app.post('/api/secure-data', (req, res) => {
    const { token, currentFingerprint } = req.body;

    try {
        const decoded = jwt.verify(token, SECRET_KEY);

        // Token geçerli olsa bile, cihaz parmak izi eşleşmiyorsa erişimi REDDET!
        if (decoded.fingerprint !== currentFingerprint) {
            console.error('🚨 SESSION HIJACKING GİRİŞİMİ ENGELLENDİ! Cihaz eşleşmedi.');
            return res.status(403).json({ error: 'Güvenlik İhlali: Farklı bir cihazdan erişim tespit edildi!' });
        }

        res.json({ data: 'Gizli verilere erişildi.', user: decoded.username });
    } catch (err) {
        res.status(401).json({ error: 'Geçersiz veya süresi dolmuş token.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[+] Security Server aktif. Port: ${PORT}`);
    console.log(`[*] Anti-Session Hijacking ve Device Fingerprinting devrede.`);
});