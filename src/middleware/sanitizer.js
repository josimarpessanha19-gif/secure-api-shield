/**
 * Recursively sanitizes input objects to prevent NoSQL injection 
 * and Cross-Site Scripting (XSS) attacks.
 */
export function sanitizer(req, res, next) {
    const sanitize = (val) => {
          if (typeof val === 'string') {
                  return val
                    .replace(/[&<>"']/g, '') // Basic XSS prevention
              .replace(/^\$/, '');     // NoSQL injection prevention
          }
          if (val && typeof val === 'object') {
                  for (const key in val) {
                            val[key] = sanitize(val[key]);
                  }
          }
          return val;
    };

  req.body = sanitize(req.body);
    req.query = sanitize(req.query);
    req.params = sanitize(req.params);

  next();
}
