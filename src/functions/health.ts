import { app } from '@azure/functions';
import { HttpRequest, HttpResponseInit } from '@azure/functions';

async function handleHealth(request: HttpRequest): Promise<HttpResponseInit> {
  try {
    // Simple health check - just return OK status
    return {
      status: 200,
      jsonBody: {
        status: 'healthy',
        service: 'bff-service',
        timestamp: new Date().toISOString(),
      },
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      status: 500,
      jsonBody: {
        status: 'unhealthy',
        service: 'bff-service',
        error: message,
        timestamp: new Date().toISOString(),
      },
    };
  }
}

// GET /api/health - Health check endpoint (public, no auth required)
app.http('healthHttp', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'health',
  handler: handleHealth,
});
