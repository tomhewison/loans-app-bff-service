import { app, HttpRequest, HttpResponseInit } from '@azure/functions';
import { logger } from '../infra/logging/logger';
import * as jwt from 'jsonwebtoken';

// Cookie configuration
const COOKIE_NAME = 'bff_access_token';
const COOKIE_MAX_AGE = 3600; // 1 hour in seconds

/**
 * Auth0 Configuration helpers
 */
function getAuth0Config() {
  const domain = process.env.AUTH0_DOMAIN;
  const clientId = process.env.AUTH0_CLIENT_ID;
  const clientSecret = process.env.AUTH0_CLIENT_SECRET;
  const audience = process.env.AUTH0_AUDIENCE;
  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';

  if (!domain || !clientId) {
    throw new Error('AUTH0_DOMAIN and AUTH0_CLIENT_ID are required');
  }

  return {
    domain: domain.replace(/\/$/, ''),
    clientId,
    clientSecret,
    audience,
    frontendUrl,
  };
}

/**
 * Builds the callback URL for Auth0
 */
function getCallbackUrl(request: HttpRequest): string {
  const host = request.headers.get('host') || 'localhost:7071';
  const protocol = request.headers.get('x-forwarded-proto') || 'http';
  return `${protocol}://${host}/api/auth/callback`;
}

/**
 * Determines if we're in production (for Secure cookie flag)
 */
function isProduction(request: HttpRequest): boolean {
  const protocol = request.headers.get('x-forwarded-proto') || 'http';
  return protocol === 'https';
}

/**
 * Creates an HttpOnly cookie header value
 * Uses SameSite=None for cross-domain support (BFF and frontend on different domains)
 */
function createCookieHeader(token: string, maxAge: number, isSecure: boolean): string {
  const parts = [
    `${COOKIE_NAME}=${token}`,
    `HttpOnly`,
    `Path=/`,
    `Max-Age=${maxAge}`,
    `SameSite=None`, // Required for cross-domain cookies
    `Secure`, // Required when SameSite=None
  ];

  return parts.join('; ');
}

/**
 * Creates a cookie header to clear the auth cookie
 */
function createClearCookieHeader(): string {
  const parts = [
    `${COOKIE_NAME}=`,
    `HttpOnly`,
    `Path=/`,
    `Max-Age=0`,
    `SameSite=None`,
    `Secure`,
  ];

  return parts.join('; ');
}

/**
 * Extracts the access token from cookies
 */
export function getTokenFromCookies(request: HttpRequest): string | null {
  const cookieHeader = request.headers.get('cookie');
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(';').map(c => c.trim());
  for (const cookie of cookies) {
    const [name, ...valueParts] = cookie.split('=');
    if (name === COOKIE_NAME) {
      return valueParts.join('='); // Handle tokens with = in them
    }
  }
  return null;
}

/**
 * GET /api/auth/login
 * Initiates the Auth0 Authorization Code Flow
 * Redirects the user to Auth0's login page
 */
async function handleLogin(request: HttpRequest): Promise<HttpResponseInit> {
  try {
    const config = getAuth0Config();
    const callbackUrl = getCallbackUrl(request);

    // Get the return URL from query params (where to redirect after login)
    const returnUrl = request.query.get('returnUrl') || config.frontendUrl;

    // Generate a state parameter (should include CSRF protection in production)
    const state = Buffer.from(JSON.stringify({ returnUrl })).toString('base64url');

    // Build the Auth0 authorization URL
    const authUrl = new URL(`https://${config.domain}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', config.clientId);
    authUrl.searchParams.set('redirect_uri', callbackUrl);
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', state);

    if (config.audience) {
      authUrl.searchParams.set('audience', config.audience);
    }

    logger.info('Initiating Auth0 login', {
      returnUrl,
      callbackUrl,
      authDomain: config.domain,
    });

    // Redirect to Auth0
    return {
      status: 302,
      headers: {
        'Location': authUrl.toString(),
      },
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.error('Failed to initiate login', error as Error);

    return {
      status: 500,
      jsonBody: {
        error: 'Login Error',
        message: 'Failed to initiate login flow',
        details: process.env.NODE_ENV === 'development' ? message : undefined,
      },
    };
  }
}

/**
 * GET /api/auth/callback
 * Handles the Auth0 callback after user authentication
 * Exchanges the authorization code for tokens and sets HttpOnly cookie
 */
async function handleCallback(request: HttpRequest): Promise<HttpResponseInit> {
  try {
    const config = getAuth0Config();
    const callbackUrl = getCallbackUrl(request);
    const isSecure = isProduction(request);

    // Get the authorization code and state from query params
    const code = request.query.get('code');
    const state = request.query.get('state');
    const error = request.query.get('error');
    const errorDescription = request.query.get('error_description');

    // Handle Auth0 errors
    if (error) {
      logger.warn('Auth0 returned an error', { error, errorDescription });
      return {
        status: 302,
        headers: {
          'Location': `${config.frontendUrl}/login?error=${encodeURIComponent(errorDescription || error)}`,
        },
      };
    }

    if (!code) {
      logger.warn('No authorization code received');
      return {
        status: 302,
        headers: {
          'Location': `${config.frontendUrl}/login?error=${encodeURIComponent('No authorization code received')}`,
        },
      };
    }

    // Decode the state to get the return URL
    let returnUrl = config.frontendUrl;
    if (state) {
      try {
        const stateData = JSON.parse(Buffer.from(state, 'base64url').toString());
        returnUrl = stateData.returnUrl || config.frontendUrl;
      } catch {
        logger.warn('Failed to decode state parameter');
      }
    }

    // Exchange the code for tokens
    logger.info('Exchanging authorization code for tokens');

    const tokenResponse = await fetch(`https://${config.domain}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code,
        redirect_uri: callbackUrl,
      }),
    });

    if (!tokenResponse.ok) {
      const errorBody = await tokenResponse.text();
      logger.error('Failed to exchange code for tokens', new Error(errorBody));
      return {
        status: 302,
        headers: {
          'Location': `${config.frontendUrl}/login?error=${encodeURIComponent('Failed to complete authentication')}`,
        },
      };
    }

    const tokens = await tokenResponse.json() as {
      access_token: string;
      id_token?: string;
      token_type: string;
      expires_in: number;
    };

    logger.info('Successfully obtained tokens, setting HttpOnly cookie');

    // Set the access token as an HttpOnly cookie and redirect
    return {
      status: 302,
      headers: {
        'Location': returnUrl,
        'Set-Cookie': createCookieHeader(tokens.access_token, tokens.expires_in || COOKIE_MAX_AGE, isSecure),
      },
    };
  } catch (error) {
    const config = getAuth0Config();
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.error('Callback handling failed', error as Error);

    return {
      status: 302,
      headers: {
        'Location': `${config.frontendUrl}/login?error=${encodeURIComponent('Authentication failed')}`,
      },
    };
  }
}

/**
 * GET /api/auth/logout
 * Clears the auth cookie and logs the user out of Auth0
 */
async function handleLogout(request: HttpRequest): Promise<HttpResponseInit> {
  try {
    const config = getAuth0Config();
    const isSecure = isProduction(request);

    // Get the return URL from query params
    const returnUrl = request.query.get('returnUrl') || config.frontendUrl;

    // Build the Auth0 logout URL
    const logoutUrl = new URL(`https://${config.domain}/v2/logout`);
    logoutUrl.searchParams.set('client_id', config.clientId);
    logoutUrl.searchParams.set('returnTo', returnUrl);

    logger.info('Initiating Auth0 logout', { returnUrl });

    // Clear the cookie and redirect to Auth0 logout
    return {
      status: 302,
      headers: {
        'Location': logoutUrl.toString(),
        'Set-Cookie': createClearCookieHeader(),
      },
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.error('Failed to initiate logout', error as Error);

    // Redirect to frontend anyway
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    return {
      status: 302,
      headers: {
        'Location': frontendUrl,
      },
    };
  }
}

/**
 * GET /api/auth/status
 * Returns the current authentication status
 * Checks if valid cookie exists and returns user info
 */
async function handleStatus(request: HttpRequest): Promise<HttpResponseInit> {
  try {
    const config = getAuth0Config();
    const accessToken = getTokenFromCookies(request);

    if (!accessToken) {
      return {
        status: 200,
        jsonBody: {
          isAuthenticated: false,
          user: null,
        },
      };
    }

    // Decode the token to extract roles (without verification, as we'll validate with Auth0)
    let roles: string[] = [];
    try {
      const decoded = jwt.decode(accessToken) as any;
      if (decoded) {
        // Check multiple possible namespaces for roles
        const potentialNamespaces = [
          `https://${config.domain}/roles`,
          'https://deviceloandevth04web.z33.web.core.windows.net/roles'
        ];

        for (const ns of potentialNamespaces) {
          if (decoded[ns] && Array.isArray(decoded[ns])) {
            roles = decoded[ns];
            logger.info(`Found roles in namespace: ${ns}`, { roles: roles.join(',') });
            break;
          }
        }
        // If no roles found in custom namespaces, check standard roles claim
        if (roles.length === 0 && decoded.roles && Array.isArray(decoded.roles)) {
          roles = decoded.roles;
          logger.info('Found roles in standard claim', { roles: roles.join(',') });
        }

        if (roles.length === 0) {
          logger.info('No roles found in token', { tokenKeys: Object.keys(decoded).join(',') });
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      logger.debug('Failed to decode token for roles', { error: message });
    }

    // Fetch user info from Auth0 to validate token
    const userInfoResponse = await fetch(`https://${config.domain}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    if (!userInfoResponse.ok) {
      logger.debug('Token validation failed', { status: userInfoResponse.status });
      return {
        status: 200,
        jsonBody: {
          isAuthenticated: false,
          user: null,
        },
      };
    }

    const userInfo = await userInfoResponse.json();

    return {
      status: 200,
      jsonBody: {
        isAuthenticated: true,
        user: {
          ...userInfo,
          roles,
        },
      },
    };
  } catch (error) {
    logger.error('Failed to check auth status', error as Error);
    return {
      status: 200,
      jsonBody: {
        isAuthenticated: false,
        user: null,
      },
    };
  }
}

/**
 * GET /api/auth/me
 * Returns the current user's information
 * Reads token from HttpOnly cookie
 */
async function handleMe(request: HttpRequest): Promise<HttpResponseInit> {
  try {
    const config = getAuth0Config();
    const accessToken = getTokenFromCookies(request);

    if (!accessToken) {
      return {
        status: 401,
        jsonBody: {
          error: 'Unauthorized',
          message: 'No access token provided',
        },
      };
    }

    // Fetch user info from Auth0
    const userInfoResponse = await fetch(`https://${config.domain}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    if (!userInfoResponse.ok) {
      const status = userInfoResponse.status === 401 ? 401 : 500;
      return {
        status,
        jsonBody: {
          error: status === 401 ? 'Unauthorized' : 'Error',
          message: 'Failed to fetch user information',
        },
      };
    }

    const userInfo = await userInfoResponse.json();

    return {
      status: 200,
      jsonBody: userInfo,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.error('Failed to fetch user info', error as Error);

    return {
      status: 500,
      jsonBody: {
        error: 'Error',
        message: 'Failed to fetch user information',
      },
    };
  }
}

// Register auth endpoints
app.http('authLogin', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'auth/login',
  handler: handleLogin,
});

app.http('authCallback', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'auth/callback',
  handler: handleCallback,
});

app.http('authLogout', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'auth/logout',
  handler: handleLogout,
});

app.http('authStatus', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'auth/status',
  handler: handleStatus,
});

app.http('authMe', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'auth/me',
  handler: handleMe,
});
