import { HttpResponseInit } from '@azure/functions';

const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:3000',
  // Add production origins from environment variable
  ...(process.env.ALLOWED_ORIGINS?.split(',') || []),
];

/**
 * Adds CORS headers to response
 */
export function addCorsHeaders(response: HttpResponseInit, origin?: string | null): HttpResponseInit {
  const requestOrigin = origin || '*';
  const allowedOrigin = ALLOWED_ORIGINS.includes(requestOrigin) ? requestOrigin : ALLOWED_ORIGINS[0] || '*';
  
  return {
    ...response,
    headers: {
      ...response.headers,
      'Access-Control-Allow-Origin': allowedOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '3600',
    },
  };
}

/**
 * Handles CORS preflight requests
 */
export function handleCorsPreflight(origin?: string | null): HttpResponseInit {
  const requestOrigin = origin || '*';
  const allowedOrigin = ALLOWED_ORIGINS.includes(requestOrigin) ? requestOrigin : ALLOWED_ORIGINS[0] || '*';
  
  return {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': allowedOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '3600',
    },
  };
}

/**
 * Checks if the request origin is allowed
 */
export function isOriginAllowed(origin: string | null | undefined): boolean {
  if (!origin) return false;
  return ALLOWED_ORIGINS.includes(origin);
}

