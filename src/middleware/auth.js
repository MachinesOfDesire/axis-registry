/**
 * Registrar Authentication Middleware
 *
 * Registrars authenticate with API keys via Bearer token.
 * The registry stores SHA-256 hashes of API keys, never the keys themselves.
 */

export async function authenticateRegistrar(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  const apiKey = authHeader.slice(7);
  const keyHash = await hashApiKey(apiKey);

  const registrar = await env.DB.prepare(
    'SELECT id, name, type, domain, status FROM registrars WHERE api_key_hash = ? AND status = ?'
  ).bind(keyHash, 'active').first();

  return registrar || null;
}

export async function hashApiKey(key) {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
