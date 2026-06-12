/**
 * jwt_middleware.ts
 * Production JWT authentication middleware for rp-tbs-exchange-api.
 * Patches: token expiry enforcement, algorithm whitelisting, claims validation.
 */

import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ALGORITHM = 'HS256' as const;
const MAX_TOKEN_AGE_SECONDS = 900; // 15 minutes — enforced in addition to exp claim

if (!JWT_SECRET) {
  throw new Error('[SECURITY] JWT_SECRET environment variable is required');
}

export interface AuthenticatedRequest extends Request {
  user?: {
    userId: string;
    role: string;
    kycVerified: boolean;
    iat: number;
    exp: number;
  };
}

export interface JWTPayload {
  userId: string;
  role: string;
  kycVerified: boolean;
  iat: number;
  exp: number;
}

/**
 * Strict JWT verification:
 * - Algorithm whitelist: HS256 only (prevents alg:none attacks)
 * - Max token age: 15 minutes (defense against long-lived stolen tokens)
 * - Required claims: userId, role, kycVerified
 * - Rejects tokens without exp claim
 */
export function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Missing or malformed Authorization header',
    });
    return;
  }

  const token = authHeader.slice(7);

  try {
    const payload = jwt.verify(token, JWT_SECRET!, {
      algorithms: [JWT_ALGORITHM],
      complete: false,
    }) as JWTPayload;

    // Enforce max token age regardless of exp claim
    const now = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp - payload.iat > MAX_TOKEN_AGE_SECONDS) {
      res.status(401).json({
        error: 'TOKEN_LIFETIME_EXCEEDED',
        message: 'Token lifetime exceeds maximum allowed duration',
      });
      return;
    }

    // Validate required claims exist
    if (!payload.userId || !payload.role || payload.kycVerified === undefined) {
      res.status(401).json({
        error: 'INVALID_TOKEN_CLAIMS',
        message: 'Token missing required claims',
      });
      return;
    }

    req.user = payload;
    next();
  } catch (err) {
    const message =
      err instanceof jwt.TokenExpiredError
        ? 'Token has expired'
        : err instanceof jwt.JsonWebTokenError
        ? 'Invalid token signature'
        : 'Token verification failed';

    res.status(401).json({ error: 'TOKEN_INVALID', message });
  }
}

/**
 * Role-based access control middleware.
 * Usage: router.post('/admin/...', requireAuth, requireRole('admin'), handler)
 */
export function requireRole(...allowedRoles: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'UNAUTHORIZED' });
      return;
    }
    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: 'FORBIDDEN',
        message: `Role '${req.user.role}' is not authorized for this resource`,
      });
      return;
    }
    next();
  };
}

/**
 * KYC verification guard — required on all order placement endpoints.
 */
export function requireKYC(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  if (!req.user?.kycVerified) {
    res.status(403).json({
      error: 'KYC_REQUIRED',
      message: 'KYC verification required to place orders',
    });
    return;
  }
  next();
}
