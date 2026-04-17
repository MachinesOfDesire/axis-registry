/**
 * CORS Middleware
 * All endpoints are CORS-open — verification must be accessible from anywhere.
 */

export const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

export function handleOptions(request) {
  return new Response(null, { status: 204, headers: corsHeaders });
}
