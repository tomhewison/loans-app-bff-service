import { DefaultAzureCredential } from '@azure/identity';
import { SecretClient } from '@azure/keyvault-secrets';
import { logger } from '../logging/logger';

let cachedSubscriptionKey: string | null = null;
let cacheExpiry: number = 0;
const CACHE_DURATION_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Gets the APIM subscription key, either from environment variable or Key Vault
 */
export async function getApimSubscriptionKey(): Promise<string> {
  // Check cache first
  if (cachedSubscriptionKey && Date.now() < cacheExpiry) {
    logger.debug('Using cached APIM subscription key');
    return cachedSubscriptionKey;
  }

  // Try environment variable first (for local development)
  const envKey = process.env.APIM_SUBSCRIPTION_KEY;
  if (envKey) {
    logger.debug('Using APIM subscription key from environment variable');
    cachedSubscriptionKey = envKey;
    cacheExpiry = Date.now() + CACHE_DURATION_MS;
    return envKey;
  }

  // Fall back to Key Vault
  const keyVaultUrl = process.env.KEY_VAULT_URL;
  const secretName = process.env.KEY_VAULT_SECRET_NAME || 'apim-subscription-key';

  if (!keyVaultUrl) {
    const error = 'APIM_SUBSCRIPTION_KEY or KEY_VAULT_URL must be configured';
    logger.error(error);
    throw new Error(error);
  }

  try {
    logger.info('Fetching APIM subscription key from Key Vault', { keyVaultUrl, secretName });

    const credential = new DefaultAzureCredential();
    const client = new SecretClient(keyVaultUrl, credential);
    const secret = await client.getSecret(secretName);

    if (!secret.value) {
      throw new Error(`Secret ${secretName} not found or has no value`);
    }

    cachedSubscriptionKey = secret.value;
    cacheExpiry = Date.now() + CACHE_DURATION_MS;

    logger.info('Successfully retrieved APIM subscription key from Key Vault');
    return secret.value;
  } catch (error) {
    logger.error('Failed to retrieve APIM subscription key from Key Vault', error as Error);
    throw error;
  }
}

/**
 * Gets the base URL for APIM
 */
export function getApimBaseUrl(): string {
  const baseUrl = process.env.APIM_BASE_URL;
  if (!baseUrl) {
    throw new Error('APIM_BASE_URL environment variable is required');
  }
  return baseUrl.replace(/\/$/, ''); // Remove trailing slash
}

export type ProxyRequestOptions = {
  method: string;
  route: string;
  headers: {
    get(name: string): string | null;
  };
  body?: string;
  accessToken?: string;
};

export type ProxyResponse = {
  status: number;
  headers: Record<string, string>;
  body: any;
};

/**
 * Forwards a request to APIM
 */
export async function forwardToApim(options: ProxyRequestOptions): Promise<ProxyResponse> {
  const { method, route, headers, body, accessToken } = options;
  const startTime = Date.now();

  const apimBaseUrl = getApimBaseUrl();
  const subscriptionKey = await getApimSubscriptionKey();
  const targetUrl = `${apimBaseUrl}/${route}`;

  logger.info('Forwarding request to APIM', { method, route, targetUrl });

  // Build headers for APIM request
  const apimHeaders: Record<string, string> = {
    'Ocp-Apim-Subscription-Key': subscriptionKey,
    'Content-Type': headers.get('content-type') || 'application/json',
  };

  // Forward Authorization header if provided
  if (accessToken) {
    apimHeaders['Authorization'] = `Bearer ${accessToken}`;
  }

  // Forward correlation ID if present
  const correlationId = headers.get('x-correlation-id');
  if (correlationId) {
    apimHeaders['x-correlation-id'] = correlationId;
  }

  try {
    const response = await fetch(targetUrl, {
      method,
      headers: apimHeaders,
      body: method !== 'GET' && method !== 'HEAD' ? body : undefined,
    });

    const duration = Date.now() - startTime;
    const success = response.ok;

    logger.trackDependency('APIM', apimBaseUrl, duration, success, {
      method,
      route,
      statusCode: response.status,
    });

    // Parse response headers
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      // Filter out headers that shouldn't be forwarded
      // Including CORS headers - BFF adds its own to avoid duplicates
      // And Content-Encoding - fetch auto-decompresses, so we don't forward compressed encoding
      const lowerKey = key.toLowerCase();
      if (!['transfer-encoding', 'connection', 'keep-alive', 'content-encoding', 'content-length'].includes(lowerKey) &&
        !lowerKey.startsWith('access-control-')) {
        responseHeaders[key] = value;
      }
    });

    // Parse response body
    let responseBody: any;
    const contentType = response.headers.get('content-type');

    if (response.status === 204) {
      responseBody = null;
    } else if (contentType?.includes('application/json')) {
      responseBody = await response.json();
    } else {
      responseBody = await response.text();
    }

    return {
      status: response.status,
      headers: responseHeaders,
      body: responseBody,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    logger.trackDependency('APIM', apimBaseUrl, duration, false, {
      method,
      route,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    throw error;
  }
}

