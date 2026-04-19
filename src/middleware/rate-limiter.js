const store = new Map();
const WINDOW = 60000;
const LIMIT = 100;

/** Clean expired entries every 5 minutes */
setInterval(() => {
    const now = Date.now();
    for (const [key, val] of store) {
          if (now - val.start > WINDOW) store.delete(key);
    }
}, 300000);

/** Rate limiter - 100 requests per minute per IP */
export function rateLimiter(req, res, next) {
    const key = req.ip;
    const now = Date.now();
    const record = store.get(key);

  if (!record || now - record.start > WINDOW) {
        store.set(key, { count: 1, start: now });
        return next();
  }

  if (++record.count > LIMIT) {
        const retry = Math.ceil((WINDOW - (now - record.start)) / 1000);
        res.set('Retry-After', String(retry));
        return res.status(429).json({ error: 'Too many requests', retryAfter: retry });
  }

  next();
}
