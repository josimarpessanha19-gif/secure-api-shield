import express from 'express';
import helmet from 'helmet';
import { rateLimiter } from './middleware/rate-limiter.js';
import { antiProxy } from './middleware/anti-proxy.js';
import { sanitizer } from './middleware/sanitizer.js';
import { verifyToken, generateToken } from './middleware/auth.js';

/**
 * Creates a secure Express application with all security
  * middlewares pre-configured. Zero config, production-ready.
   * 
    * @param {Object} options - Configuration overrides
     * @returns {{ app: Express, verifyToken: Function, generateToken: Function }}
      */
      export function createSecureApp(options = {}) {
        const app = express();

          // --- Base Security ---
            app.use(helmet());
              app.use(express.json({ limit: '10kb' }));
                app.disable('x-powered-by');

                  // --- Custom Middlewares ---
                    app.use(rateLimiter);
                      app.use(antiProxy);
                        app.use(sanitizer);

                          // --- Health Check ---
                            app.get('/health', (_req, res) => {
                                res.json({ status: 'ok', timestamp: new Date().toISOString() });
                                  });

                                    return { app, verifyToken, generateToken };
                                    }

                                    // --- Standalone Server ---
                                    if (process.argv[1] === import.meta.filename) {
                                      const { app } = createSecureApp();
                                        const PORT = process.env.PORT || 3000;

                                          app.listen(PORT, () => {
                                              console.log(`[Shield] Secure server running on port ${PORT}`);
                                                });
                                                }
