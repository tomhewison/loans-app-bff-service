import { app } from '@azure/functions';
import { HttpRequest, HttpResponseInit } from '@azure/functions';
import { handleCorsPreflight } from '../infra/middleware/cors';

async function handleOptions(request: HttpRequest): Promise<HttpResponseInit> {
  return handleCorsPreflight(request.headers.get('origin'));
}

// Handle CORS preflight for all endpoints
app.http('optionsHandler', {
  methods: ['OPTIONS'],
  authLevel: 'anonymous',
  route: '{*path}',
  handler: handleOptions,
});

