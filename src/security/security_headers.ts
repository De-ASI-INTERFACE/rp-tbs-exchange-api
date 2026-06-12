/**
 * security_headers.ts
 * HTTP security headers middleware for rp-tbs-exchange-api Express app.
 * Patches: CSP, HSTS, CORS hardening, X-Frame-Options.
 */

import { Request, Response, NextFunction } from 'express';
import { randomBytes } from 'crypto';

const ALLOWED_ORIGINS = new Set(
  (process.env.ALLOWED_ORIGINS ?? 'http://localhost:3000')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean)
);

/**
 * Apply production security headers to every response.
 * Must be registered as the FIRST middleware in the Express chain.
 */
export function securityHeaders(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const nonce = randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;

  // Content Security Policy
  res.setHeader(
    'Content-Security-Policy',
    [
      `default-src 'self'`,
      `script-src 'self' 'nonce-${nonce}'`,
      `style-src 'self' 'unsafe-inline'`,
      `img-src 'self' data: https:`,
      `connect-src 'self' wss: https:`,
      `frame-ancestors 'none'`,
      `base-uri 'self'`,
      `form-action 'self'`,
    ].join('; ')
  );

  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.removeHeader('X-Powered-By'); // Remove Express fingerprint

  next();
}

/**
 * CORS middleware with strict origin whitelist.
 * No wildcard `*` in production.
 */
export function corsMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const origin = req.headers.origin;

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization,Content-Type,X-Request-ID');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
  }

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  next();
}
