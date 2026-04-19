<div align="center">
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

📧 josimarpessanha19@gmail.com · [LinkedIn](https://www.linkedin.com/in/josimar-pessanha-de-aguiar-545398404/) · [GitHub](https://github.com/josimarpessanha19-gif)
