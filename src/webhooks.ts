import crypto from 'node:crypto';

/**
 * HMAC-SHA256 signature verifier for Huudis webhooks.
 *
 * Huudis signs every delivery with:
 *   X-Huudis-Signature: t=<unix_seconds>,v1=<hex>
 * where <hex> = HMAC-SHA256(secret, `${t}.${rawBody}`).
 *
 * Usage (Express):
 *
 *   import express from 'express';
 *   import { verifyWebhookSignature } from '@forjio/huudis-node';
 *
 *   const app = express();
 *   app.post('/webhooks/huudis', express.raw({ type: 'application/json' }), (req, res) => {
 *     const sig = req.header('X-Huudis-Signature') ?? '';
 *     const raw = req.body as Buffer;  // express.raw gives us bytes
 *     if (!verifyWebhookSignature(raw, sig, process.env.HUUDIS_WEBHOOK_SECRET!)) {
 *       return res.sendStatus(400);
 *     }
 *     const event = JSON.parse(raw.toString('utf8'));
 *     // handle event...
 *     res.sendStatus(204);
 *   });
 *
 * The rawBody matters — verifying the already-parsed JSON will re-stringify
 * it with different whitespace and the signature will never match. Always
 * use express.raw() (or the equivalent) on the webhook route.
 */

export interface VerifyOptions {
  /**
   * Reject signatures with a timestamp older than this many seconds.
   * Defaults to 300 (5 minutes) — matches Stripe/GitHub conventions.
   * Protects against replay attacks if an attacker captures a signed
   * request and tries to re-deliver it later.
   */
  toleranceSeconds?: number;
  /**
   * Inject a clock for tests. Returns the "now" timestamp in seconds.
   */
  now?: () => number;
}

interface ParsedSignature {
  timestamp: number;
  v1: string;
}

function parseSignatureHeader(header: string): ParsedSignature | null {
  const parts = header.split(',').map((p) => p.trim());
  let timestamp: number | null = null;
  let v1: string | null = null;
  for (const part of parts) {
    const [k, v] = part.split('=');
    if (k === 't' && v) timestamp = Number(v);
    else if (k === 'v1' && v) v1 = v;
  }
  if (timestamp === null || Number.isNaN(timestamp) || !v1) return null;
  return { timestamp, v1 };
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  } catch {
    return false;
  }
}

export function verifyWebhookSignature(
  rawBody: string | Buffer,
  signatureHeader: string,
  secret: string,
  options: VerifyOptions = {},
): boolean {
  if (!signatureHeader || !secret) return false;
  const parsed = parseSignatureHeader(signatureHeader);
  if (!parsed) return false;

  const tolerance = options.toleranceSeconds ?? 300;
  const now = options.now ? options.now() : Math.floor(Date.now() / 1000);
  if (Math.abs(now - parsed.timestamp) > tolerance) return false;

  const body = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${parsed.timestamp}.${body}`)
    .digest('hex');

  return timingSafeEqualHex(expected, parsed.v1);
}
