require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

// Sahte Veritabanı (Gerçekte MongoDB/PostgreSQL olacak)
const users = [{ id: 1, username: 'taha', password: 'password123', role: 'admin' }];

// --- LOGİN ENDPOINT ---
app.post('/api/login', (req, res) => {
    const { username, password, clientFingerprint } = req.body;

    const user = users.find(u => u.username === username && u.password === password);

    if (!user) {
        return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı!' });
    }

    if (!clientFingerprint) {
        return res.status(400).json({ error: 'Güvenlik İhlali: Cihaz Parmak İzi (Fingerprint) bulunamadı!' });
    }

    // Token'ın kalbine cihaz kimliğini mühürlüyoruz (Device Binding)
    const payload = {
        id: user.id,
        role: user.role,
        deviceId: clientFingerprint 
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h' });

    // Token'ı XSS saldırılarından korumak için HTTP-Only Cookie olarak basıyoruz
    res.cookie('auth_token', token, {
        httpOnly: true,  // Tarayıcıdaki JavaScript (ör. eklentiler) bu cookie'yi okuyamaz!
        secure: false,   // Canlıya alırken (HTTPS) bunu 'true' yapacağız.
        sameSite: 'Strict', // CSRF saldırılarını engeller.
        maxAge: 2 * 60 * 60 * 1000 // 2 saat
    });

    res.json({ message: 'Giriş Başarılı! Token güvenli bir şekilde cihaza mühürlendi.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🛡️ Güvenli API Ayakta: http://localhost:${PORT}`);
});