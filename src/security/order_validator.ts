/**
 * order_validator.ts
 * Financial order validation for rp-tbs-exchange-api.
 * Patches: amount bounds, slippage cap, idempotency key enforcement.
 */

import { z } from 'zod';

const MAX_SLIPPAGE_BPS = parseInt(process.env.MAX_SLIPPAGE_BPS ?? '300', 10); // 3% default
const MAX_ORDER_USD = parseFloat(process.env.MAX_ORDER_USD ?? '100000');
const MIN_ORDER_USD = parseFloat(process.env.MIN_ORDER_USD ?? '0.01');

export const OrderSide = z.enum(['buy', 'sell']);
export const OrderType = z.enum(['market', 'limit', 'stop_limit']);

export const OrderSchema = z.object({
  idempotencyKey: z
    .string()
    .uuid('idempotencyKey must be a valid UUID v4')
    .describe('Unique key to prevent duplicate order submission'),
  symbol: z
    .string()
    .regex(/^[A-Z]{2,10}-[A-Z]{2,10}$/, 'Symbol must be in BASE-QUOTE format (e.g., BTC-USD)'),
  side: OrderSide,
  type: OrderType,
  baseSize: z
    .number()
    .positive('baseSize must be positive')
    .max(1e15, 'baseSize exceeds safe maximum')
    .refine((v) => isFinite(v), 'baseSize must be finite'),
  limitPrice: z
    .number()
    .positive()
    .max(1e12)
    .optional()
    .refine((v) => v === undefined || isFinite(v), 'limitPrice must be finite'),
  slippageBps: z
    .number()
    .int('slippageBps must be an integer')
    .min(0)
    .max(MAX_SLIPPAGE_BPS, `slippageBps cannot exceed platform maximum of ${MAX_SLIPPAGE_BPS} bps`)
    .optional()
    .default(50),
}).strict();

export type OrderRequest = z.infer<typeof OrderSchema>;

/**
 * Validate and parse an incoming order payload.
 * Returns { success: true, data } or { success: false, errors }.
 */
export function validateOrder(payload: unknown): 
  | { success: true; data: OrderRequest }
  | { success: false; errors: z.ZodIssue[] } {
  const result = OrderSchema.safeParse(payload);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, errors: result.error.issues };
}

/**
 * Validate order notional value against platform limits.
 * price * size must be within [MIN_ORDER_USD, MAX_ORDER_USD].
 */
export function validateOrderNotional(
  baseSize: number,
  price: number,
): { valid: boolean; reason?: string } {
  if (!isFinite(price) || price <= 0) {
    return { valid: false, reason: 'Invalid price for notional calculation' };
  }
  const notional = baseSize * price;
  if (notional < MIN_ORDER_USD) {
    return { valid: false, reason: `Order notional $${notional.toFixed(4)} below minimum $${MIN_ORDER_USD}` };
  }
  if (notional > MAX_ORDER_USD) {
    return { valid: false, reason: `Order notional $${notional.toFixed(2)} exceeds maximum $${MAX_ORDER_USD}` };
  }
  return { valid: true };
}
