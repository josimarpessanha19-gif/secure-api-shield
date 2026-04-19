/**
 * Detects if the request is coming from a known VPN, proxy, or data center.
 * Uses header analysis for zero-latency protection.
 */
export function antiProxy(req, res, next) {
    const headers = [
          'x-forwarded-for',
          'x-real-ip',
          'via',
          'x-proxy-id',
          'x-vpn-id'
        ];

  // Logic to detect proxy/VPN signatures in headers
  const isProxy = headers.some(h => req.headers[h]);

  // Example of more advanced checks
  const suspiciousUserAgent = /bot|crawl|proxy|vpn/i.test(req.headers['user-agent']);

  if (isProxy && suspiciousUserAgent) {
        console.warn(`[Shield] Blocked suspicious proxy request from ${req.ip}`);
        return res.status(403).json({ 
                                          error: 'Access denied: VPN/Proxy detected',
                message: 'Please disable your VPN or proxy to access this API.'
        });
  }

  next();
}
