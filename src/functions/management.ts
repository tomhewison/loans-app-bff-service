import { app, HttpRequest, HttpResponseInit } from '@azure/functions';
import { getTokenFromCookies } from './auth';
import { logger } from '../infra/logging/logger';
import * as jwt from 'jsonwebtoken';

// Management service configuration
function getManagementServiceUrl(): string {
    const url = process.env.APIM_BASE_URL;
    if (!url) {
        throw new Error('APIM_BASE_URL environment variable is required');
    }
    return url.replace(/\/$/, '');
}

function getApimSubscriptionKey(): string | undefined {
    return process.env.APIM_SUBSCRIPTION_KEY;
}

/**
 * Check if user has the staff role
 */
function hasStaffRole(accessToken: string): boolean {
    try {
        const decoded = jwt.decode(accessToken) as any;
        if (!decoded) return false;

        const domain = process.env.AUTH0_DOMAIN?.replace(/\/$/, '') || '';
        const rolesNamespace = `https://${domain}/roles`;

        // Check custom namespace first
        if (decoded[rolesNamespace] && Array.isArray(decoded[rolesNamespace])) {
            return decoded[rolesNamespace].includes('staff');
        }

        // Fallback to standard roles claim
        if (decoded.roles && Array.isArray(decoded.roles)) {
            return decoded.roles.includes('staff');
        }

        return false;
    } catch (error) {
        logger.error('Failed to decode token for staff check', error as Error);
        return false;
    }
}

/**
 * Proxy requests to the management service with staff role check
 */
async function proxyToManagementService(
    request: HttpRequest,
    endpoint: string
): Promise<HttpResponseInit> {
    try {
        const accessToken = getTokenFromCookies(request);

        if (!accessToken) {
            return {
                status: 401,
                jsonBody: {
                    error: 'Unauthorized',
                    message: 'Authentication required',
                },
            };
        }

        // Check if user has staff role
        if (!hasStaffRole(accessToken)) {
            logger.warn('Non-staff user attempted to access management endpoint', { endpoint });
            return {
                status: 403,
                jsonBody: {
                    error: 'Forbidden',
                    message: 'Staff access required',
                },
            };
        }

        const managementUrl = getManagementServiceUrl();
        const subscriptionKey = getApimSubscriptionKey();

        // Build the full URL with query parameters
        const url = new URL(`${managementUrl}${endpoint}`);
        request.query.forEach((value, key) => {
            url.searchParams.set(key, value);
        });

        logger.info('Proxying request to management service', { endpoint, url: url.toString() });

        // Prepare headers
        const headers: Record<string, string> = {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
        };

        if (subscriptionKey) {
            headers['Ocp-Apim-Subscription-Key'] = subscriptionKey;
        }

        // Forward the request to the management service
        const response = await fetch(url.toString(), {
            method: request.method,
            headers,
        });

        const responseData = await response.json();

        return {
            status: response.status,
            jsonBody: responseData,
        };
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        logger.error('Management service proxy error', { error: message, endpoint });

        return {
            status: 500,
            jsonBody: {
                error: 'Proxy Error',
                message: 'Failed to communicate with management service',
            },
        };
    }
}

/**
 * GET /api/admin/dashboard/stats
 * Get dashboard statistics (staff only)
 */
async function handleDashboardStats(request: HttpRequest): Promise<HttpResponseInit> {
    return proxyToManagementService(request, '/api/dashboard/stats');
}

/**
 * GET /api/admin/reservations
 * List all reservations with optional filters (staff only)
 */
async function handleListReservations(request: HttpRequest): Promise<HttpResponseInit> {
    return proxyToManagementService(request, '/api/admin/reservations');
}

/**
 * GET /api/admin/reservations/overdue
 * List overdue reservations (staff only)
 */
async function handleListOverdue(request: HttpRequest): Promise<HttpResponseInit> {
    return proxyToManagementService(request, '/api/admin/reservations/overdue');
}

/**
 * GET /api/admin/reservations/pending
 * List pending collections (staff only)
 */
async function handleListPending(request: HttpRequest): Promise<HttpResponseInit> {
    return proxyToManagementService(request, '/api/admin/reservations/pending');
}

// Register management endpoints
app.http('getDashboardStats', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'admin/dashboard/stats',
    handler: handleDashboardStats,
});

app.http('listAdminReservations', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'admin/reservations',
    handler: handleListReservations,
});

app.http('listOverdueReservations', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'admin/reservations/overdue',
    handler: handleListOverdue,
});

app.http('listPendingCollections', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'admin/reservations/pending',
    handler: handleListPending,
});
