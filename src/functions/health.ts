import { app } from '@azure/functions';
import { HttpRequest, HttpResponseInit } from '@azure/functions';
import { addCorsHeaders } from '../infra/middleware/cors';

async function handleHealth(request: HttpRequest): Promise<HttpResponseInit> {
  const origin = request.headers.get('origin');
  
  try {
    // Simple health check - just return OK status
    return addCorsHeaders({
      status: 200,
      jsonBody: {
        status: 'healthy',
        service: 'bff-service',
        timestamp: new Date().toISOString(),
      },
    }, origin);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return addCorsHeaders({
      status: 500,
      jsonBody: {
        status: 'unhealthy',
        service: 'bff-service',
        error: message,
        timestamp: new Date().toISOString(),
      },
    }, origin);
  }
}

// GET /api/health - Health check endpoint (public, no auth required)
app.http('healthHttp', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'health',
  handler: handleHealth,
});

