# 🛡️ Legendary L2: Session Hijacking Prevention & Fingerprinting

![Status](https://img.shields.io/badge/Status-Legendary_Level-gold.svg)
![Security](https://img.shields.io/badge/Security-Session_Hijacking-red.svg)
![Web](https://img.shields.io/badge/Web-JavaScript-yellow.svg)

---

### 🎓 Academic Context
- **Institution:** Istanbul Istinye University — SecOps Courses
- **Supervisor:** Prof. Keyvan Arasteh
- **Project:** Advanced Device Fingerprinting to mitigate JWT theft.

---

## 🔍 Overview
This project implements a multi-layered security architecture designed to prevent **Session Hijacking**. By generating a unique **Device Fingerprint** on the client side and validating it against the session token on the server, we ensure that stolen tokens cannot be used by unauthorized devices.

---

## 🏗️ Architecture
- **`src/server.js`**: Node.js/Express server handling session validation.
- **`src/utils/fingerprint.js`**: Core fingerprinting logic.
- **`public/index.html`**: Client-side implementation.

---

## ✨ Key Features
- ✅ **Browser Fingerprinting:** Extracts hardware concurrency, screen resolution, and browser headers.
- ✅ **Token-Fingerprint Binding:** Each JWT is cryptographically linked to the device's unique ID.
- ✅ **Real-time Blocking:** Sessions are automatically invalidated if accessed from a new device fingerprint.

---

## 🚀 Setup & Installation
```bash
npm install
npm start
```

---

## 📽️ Demo
The following demo validates the hijacking prevention mechanism using Antigravity AI.

![Project Demo](./demo/project-demo.webp)

---
*Developed for the Web Security & Malware Analysis academic project.*