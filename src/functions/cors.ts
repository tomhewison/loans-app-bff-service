import { app, HttpRequest, HttpResponse } from '@azure/functions';

// Parse allowed origins
const envOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(o => o.length > 0);

const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:3000',
  ...envOrigins,
];

async function handleOptions(request: HttpRequest): Promise<HttpResponse> {
  const origin = request.headers.get('origin') || '*';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0] || '*';

  console.log('[CORS] Preflight request:', { origin, allowedOrigin, allAllowedOrigins: ALLOWED_ORIGINS });

  const response = new HttpResponse({
    status: 204,
  });

  response.headers.set('Access-Control-Allow-Origin', allowedOrigin);
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  response.headers.set('Access-Control-Allow-Credentials', 'true');
  response.headers.set('Access-Control-Max-Age', '3600');

  return response;
}

// Handle CORS preflight for all endpoints
app.http('optionsHandler', {
  methods: ['OPTIONS'],
  authLevel: 'anonymous',
  route: '{*path}',
  handler: handleOptions,
});

