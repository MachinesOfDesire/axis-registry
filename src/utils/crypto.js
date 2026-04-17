/**
 * Cryptographic Utilities
 * Ed25519 key operations using Web Crypto API (Cloudflare Workers)
 */

/**
 * Derive an agent ID from an Ed25519 public key.
 * SHA-256 hash of the raw 32-byte key, first 16 bytes, Base58btc encoded.
 */
export async function deriveAgentId(publicKeyBase64url) {
  const keyBytes = base64urlToBytes(publicKeyBase64url);
  const hash = await crypto.subtle.digest('SHA-256', keyBytes);
  const first16 = new Uint8Array(hash).slice(0, 16);
  return bytesToBase58(first16);
}

/**
 * Verify an Ed25519 signature.
 */
export async function verifyEd25519Signature(publicKeyBase64url, message, signatureBase64url) {
  try {
    const keyBytes = base64urlToBytes(publicKeyBase64url);
    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
    const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    const sigBytes = base64urlToBytes(signatureBase64url);
    return await crypto.subtle.verify('Ed25519', key, sigBytes, msgBytes);
  } catch (err) {
    console.error('Signature verification error:', err);
    return false;
  }
}

/**
 * Generate a random verification token.
 */
export function generateToken(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Generate a unique credential ID.
 */
export function generateCredentialId(prefix, namespace) {
  const randomPart = generateToken(8);
  return `${prefix}:${namespace}:${randomPart}`;
}

// ---- Encoding utilities ----

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function bytesToBase58(bytes) {
  let num = BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  let result = '';
  while (num > 0n) {
    const remainder = num % 58n;
    result = BASE58_ALPHABET[Number(remainder)] + result;
    num = num / 58n;
  }
  // Handle leading zeros
  for (const byte of bytes) {
    if (byte === 0) result = '1' + result;
    else break;
  }
  return result || '1';
}

export function base64urlToBytes(str) {
  // Check for multibase prefix 'z' (base58btc)
  // Only treat as base58 if it starts with 'z' AND contains no base64url-specific characters
  if (str.startsWith('z') && !str.includes('-') && !str.includes('_') && !str.includes('+') && !str.includes('/')) {
    // Additional check: base58 alphabet doesn't include 0, O, I, l
    const afterZ = str.slice(1);
    const isBase58 = [...afterZ].every(c => BASE58_ALPHABET.includes(c));
    if (isBase58) {
      return base58ToBytes(afterZ);
    }
  }
  // Standard base64url
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  return new Uint8Array([...binary].map(c => c.charCodeAt(0)));
}

export function base58ToBytes(str) {
  let num = 0n;
  for (const char of str) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base58 character: ${char}`);
    num = num * 58n + BigInt(idx);
  }
  const hex = num.toString(16).padStart(2, '0');
  const paddedHex = hex.length % 2 ? '0' + hex : hex;
  const bytes = [];
  for (let i = 0; i < paddedHex.length; i += 2) {
    bytes.push(parseInt(paddedHex.slice(i, i + 2), 16));
  }
  // Handle leading 1s (zeros in base58)
  for (const char of str) {
    if (char === '1') bytes.unshift(0);
    else break;
  }
  return new Uint8Array(bytes);
}

export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function bytesToBase64url(bytes) {
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
