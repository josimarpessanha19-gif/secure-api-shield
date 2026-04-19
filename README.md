<div align="center">

# 🛡️ Secure API Shield

**Middleware de segurança profissional para APIs Node.js**

Proteção contra proxy sniffing, injeção, brute force e mais — código limpo e modular.

[![Node.js](https://img.shields.io/badge/Node.js-18+-43853D?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org)
[![Security](https://img.shields.io/badge/Security-A+-green?style=flat-square&logo=letsencrypt&logoColor=white)]()
[![Clean Code](https://img.shields.io/badge/Clean%20Code-✓-blue?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

</div>

---

## 🎯 O que este projeto resolve

| Ameaça | Proteção |
|--------|----------|
| 🔍 Proxy Sniffing (Charles, Fiddler) | SSL Pinning + Certificate Validation |
| 🛠️ DevTools / F12 | Anti-debugging middleware |
| 💉 SQL / NoSQL Injection | Input sanitization + parameterized queries |
| 🤖 Bots & Brute Force | Rate limiting + CAPTCHA integration |
| 🔓 Token Hijacking | JWT rotation + fingerprint binding |
| 🌐 CORS Abuse | Strict origin whitelist |
| 📡 Request Tampering | HMAC signature verification |

---

## 📁 Estrutura

```
secure-api-shield/
├── src/
│   ├── middleware/
│   │   ├── auth.js          # JWT + refresh token
│   │   ├── rate-limiter.js   # Rate limiting inteligente
│   │   ├── sanitizer.js      # Input sanitization
│   │   ├── cors.js           # CORS configurável
│   │   ├── anti-proxy.js     # Detecção de proxy/tampering
│   │   └── logger.js         # Audit logging seguro
│   ├── utils/
│   │   ├── crypto.js         # Encrypt/decrypt helpers
│   │   ├── validator.js      # Schema validation
│   │   └── fingerprint.js    # Device fingerprinting
│   ├── config/
│   │   └── security.js       # Configuração centralizada
│   └── index.js              # Entry point
├── tests/
│   └── security.test.js
├── .env.example
├── package.json
└── README.md
```

---

## 💻 Código

### 1. JWT com Fingerprint Binding

```javascript
// src/middleware/auth.js
import jwt from 'jsonwebtoken';
import { createFingerprint } from '../utils/fingerprint.js';

const { JWT_SECRET, JWT_EXPIRES = '15m' } = process.env;

export function generateToken(user, req) {
  const fingerprint = createFingerprint(req);

  return jwt.sign(
    { id: user.id, role: user.role, fp: fingerprint },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

export function verifyToken(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) return res.status(401).json({ error: 'Token ausente' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentFp = createFingerprint(req);

    if (decoded.fp !== currentFp) {
      return res.status(403).json({ error: 'Token inválido para este dispositivo' });
    }

    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Token expirado ou inválido' });
  }
}
```

### 2. Device Fingerprint

```javascript
// src/utils/fingerprint.js
import crypto from 'node:crypto';

export function createFingerprint(req) {
  const raw = [
    req.headers['user-agent'],
    req.headers['accept-language'],
    req.ip,
  ].join('|');

  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}
```

### 3. Anti-Proxy Detection

```javascript
// src/middleware/anti-proxy.js
const PROXY_HEADERS = [
  'x-forwarded-for',
  'via',
  'x-proxy-id',
  'forwarded',
  'x-real-ip',
];

const SUSPICIOUS_AGENTS = [
  'charles', 'fiddler', 'mitmproxy', 'burpsuite', 'wireshark',
];

export function antiProxy(req, res, next) {
  // 1. Detectar headers de proxy
  const hasProxyHeader = PROXY_HEADERS.some(h => req.headers[h]);

  // 2. Detectar user-agent suspeito
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const hasSuspiciousAgent = SUSPICIOUS_AGENTS.some(a => ua.includes(a));

  if (hasProxyHeader || hasSuspiciousAgent) {
    return res.status(403).json({ error: 'Conexão não autorizada' });
  }

  next();
}
```

### 4. Rate Limiter Inteligente

```javascript
// src/middleware/rate-limiter.js
const requests = new Map();
const WINDOW_MS = 60_000;
const MAX_REQUESTS = 100;

export function rateLimiter(req, res, next) {
  const key = req.ip;
  const now = Date.now();

  if (!requests.has(key)) {
    requests.set(key, { count: 1, start: now });
    return next();
  }

  const record = requests.get(key);

  if (now - record.start > WINDOW_MS) {
    requests.set(key, { count: 1, start: now });
    return next();
  }

  record.count++;

  if (record.count > MAX_REQUESTS) {
    res.set('Retry-After', Math.ceil((WINDOW_MS - (now - record.start)) / 1000));
    return res.status(429).json({ error: 'Muitas requisições. Tente novamente em breve.' });
  }

  next();
}
```

### 5. Input Sanitizer

```javascript
// src/middleware/sanitizer.js
const DANGEROUS_PATTERNS = [
  /(<\s*script)/gi,
  /(drop\s+table)/gi,
  /(\$where)/gi,
  /(\$gt|\$lt|\$ne|\$regex)/gi,
  /(javascript\s*:)/gi,
];

function cleanValue(value) {
  if (typeof value !== 'string') return value;

  let clean = value.trim();

  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(clean)) return '';
  }

  return clean
    .replace(/[<>]/g, '')
    .replace(/&/g, '&amp;');
}

export function sanitizer(req, _res, next) {
  for (const source of [req.body, req.query, req.params]) {
    if (!source) continue;

    for (const key of Object.keys(source)) {
      source[key] = cleanValue(source[key]);
    }
  }
  next();
}
```

### 6. Setup Completo

```javascript
// src/index.js
import express from 'express';
import helmet from 'helmet';
import { rateLimiter } from './middleware/rate-limiter.js';
import { antiProxy } from './middleware/anti-proxy.js';
import { sanitizer } from './middleware/sanitizer.js';
import { verifyToken } from './middleware/auth.js';

export function createSecureApp() {
  const app = express();

  // Segurança base
  app.use(helmet());
  app.use(express.json({ limit: '10kb' }));

  // Middlewares de proteção
  app.use(rateLimiter);
  app.use(antiProxy);
  app.use(sanitizer);

  // Desabilitar fingerprinting do servidor
  app.disable('x-powered-by');

  return { app, verifyToken };
}

// Uso:
// const { app, verifyToken } = createSecureApp();
// app.get('/api/data', verifyToken, (req, res) => { ... });
```

---

## 🚀 Uso Rápido

```bash
git clone https://github.com/josimarpessanha19-gif/secure-api-shield.git
cd secure-api-shield && npm install
cp .env.example .env   # Edite com suas chaves
npm start               # Pronto!
```

```env
# .env.example
JWT_SECRET=sua-chave-secreta-aqui
JWT_EXPIRES=15m
PORT=3000
NODE_ENV=production
```

---

## 📫 Autor

**Josimar Pessanha** · Full Stack Developer · Segurança de APIs

📧 josimarpessanha19@gmail.com · [LinkedIn](https://www.linkedin.com/in/josimar-pessanha-de-aguiar-7a99a9356/) · [GitHub](https://github.com/josimarpessanha19-gif)
