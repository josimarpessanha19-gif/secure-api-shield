import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

const SECRET = process.env.JWT_SECRET || 'change-me';
const EXPIRES = process.env.JWT_EXPIRES || '15m';

/** Generate device fingerprint from request headers */
function fingerprint(req) {
    const raw = `${req.headers['user-agent']}|${req.headers['accept-language']}|${req.ip}`;
    return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

/** Create a JWT bound to the user's device */
export function generateToken(user, req) {
    return jwt.sign(
      { id: user.id, role: user.role, fp: fingerprint(req) },
          SECRET,
      { expiresIn: EXPIRES },
        );
}

/** Verify JWT and validate device fingerprint */
export function verifyToken(req, res, next) {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'Token required' });
    }

  try {
        const decoded = jwt.verify(header.slice(7), SECRET);

      if (decoded.fp !== fingerprint(req)) {
              return res.status(403).json({ error: 'Token mismatch' });
      }

      req.user = decoded;
        next();
  } catch {
        res.status(401).json({ error: 'Invalid or expired token' });
  }
}
