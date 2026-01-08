import { app, HttpRequest, HttpResponseInit } from '@azure/functions';
import { addCorsHeaders } from '../infra/middleware/cors';
import { forwardToApim } from '../infra/services/apim-client';
import { validateAuth0Token } from '../infra/middleware/auth0-middleware';
import { logger } from '../infra/logging/logger';

/**
 * Proxy handler - forwards requests to APIM with subscription key injection
 * 
 * Routes:
 * - GET/POST/PUT/DELETE /api/proxy/{*route} -> APIM /{route}
 */
async function handleProxy(request: HttpRequest): Promise<HttpResponseInit> {
  const origin = request.headers.get('origin');
  const route = request.params.route || '';
  const method = request.method;

  const operation = logger.startOperation('proxy', request.headers.get('x-correlation-id') || undefined);

  try {
    operation.logger.info('Proxy request received', { method, route });

    // Validate authentication if Authorization header is present
    let accessToken: string | undefined;
    const authHeader = request.headers.get('authorization');

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const validation = await validateAuth0Token(request);

      if (!validation.valid) {
        operation.logger.warn('Authentication failed', { error: validation.error });
        operation.end(false);
        return addCorsHeaders({
          status: 401,
          jsonBody: {
            error: 'Unauthorized',
            message: validation.error,
          },
        }, origin);
      }

      // Extract the token to forward to APIM
      accessToken = authHeader.substring(7);
      operation.logger.debug('User authenticated', { userId: validation.user?.sub });
    }

    // Get request body for non-GET requests
    let body: string | undefined;
    if (method !== 'GET' && method !== 'HEAD') {
      try {
        body = await request.text();
      } catch {
        // No body or couldn't read it
      }
    }

    // Forward to APIM
    const response = await forwardToApim({
      method,
      route,
      headers: request.headers,
      body,
      accessToken,
    });

    operation.logger.info('Proxy request completed', {
      method,
      route,
      status: response.status,
    });
    operation.end(response.status < 400);

    // Return the response with CORS headers
    return addCorsHeaders({
      status: response.status,
      headers: response.headers,
      jsonBody: response.body,
    }, origin);

  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    operation.logger.error('Proxy request failed', error as Error, { method, route });
    operation.end(false);

    return addCorsHeaders({
      status: 502,
      jsonBody: {
        error: 'Bad Gateway',
        message: 'Failed to forward request to backend service',
        details: process.env.NODE_ENV === 'development' ? message : undefined,
      },
    }, origin);
  }
}

// Register proxy endpoints for all HTTP methods
app.http('proxyGet', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'proxy/{*route}',
  handler: handleProxy,
});

app.http('proxyPost', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'proxy/{*route}',
  handler: handleProxy,
});

app.http('proxyPut', {
  methods: ['PUT'],
  authLevel: 'anonymous',
  route: 'proxy/{*route}',
  handler: handleProxy,
});

app.http('proxyPatch', {
  methods: ['PATCH'],
  authLevel: 'anonymous',
  route: 'proxy/{*route}',
  handler: handleProxy,
});

app.http('proxyDelete', {
  methods: ['DELETE'],
  authLevel: 'anonymous',
  route: 'proxy/{*route}',
  handler: handleProxy,
});

// CORS preflight handler for proxy routes
app.http('proxyOptions', {
  methods: ['OPTIONS'],
  authLevel: 'anonymous',
  route: 'proxy/{*route}',
  handler: async (request) => {
    const origin = request.headers.get('origin');
    return addCorsHeaders({ status: 204 }, origin);
  },
});

