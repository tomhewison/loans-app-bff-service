import { app, HttpRequest, HttpResponseInit } from '@azure/functions';
import { addCorsHeaders } from '../infra/middleware/cors';
import { logger } from '../infra/logging/logger';

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
 * GET /api/auth/login
 * Initiates the Auth0 Authorization Code Flow
 * Redirects the user to Auth0's login page
 */
async function handleLogin(request: HttpRequest): Promise<HttpResponseInit> {
  const origin = request.headers.get('origin');
  
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
    
    return addCorsHeaders({
      status: 500,
      jsonBody: {
        error: 'Login Error',
        message: 'Failed to initiate login flow',
        details: process.env.NODE_ENV === 'development' ? message : undefined,
      },
    }, origin);
  }
}

/**
 * GET /api/auth/callback
 * Handles the Auth0 callback after user authentication
 * Exchanges the authorization code for tokens
 */
async function handleCallback(request: HttpRequest): Promise<HttpResponseInit> {
  const origin = request.headers.get('origin');
  
  try {
    const config = getAuth0Config();
    const callbackUrl = getCallbackUrl(request);
    
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
    
    logger.info('Successfully obtained tokens');
    
    // Redirect back to the frontend with the token
    // In a more secure implementation, you would:
    // 1. Store the token in an HttpOnly cookie
    // 2. Or store it server-side and return a session ID
    // For simplicity, we're passing it as a URL fragment (client-side only)
    const redirectUrl = new URL(returnUrl);
    redirectUrl.hash = `access_token=${tokens.access_token}&token_type=${tokens.token_type}&expires_in=${tokens.expires_in}`;
    
    return {
      status: 302,
      headers: {
        'Location': redirectUrl.toString(),
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
 * Logs the user out of Auth0
 */
async function handleLogout(request: HttpRequest): Promise<HttpResponseInit> {
  try {
    const config = getAuth0Config();
    
    // Get the return URL from query params
    const returnUrl = request.query.get('returnUrl') || config.frontendUrl;
    
    // Build the Auth0 logout URL
    const logoutUrl = new URL(`https://${config.domain}/v2/logout`);
    logoutUrl.searchParams.set('client_id', config.clientId);
    logoutUrl.searchParams.set('returnTo', returnUrl);

    logger.info('Initiating Auth0 logout', { returnUrl });

    return {
      status: 302,
      headers: {
        'Location': logoutUrl.toString(),
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
 * GET /api/auth/me
 * Returns the current user's information
 * Requires a valid Bearer token
 */
async function handleMe(request: HttpRequest): Promise<HttpResponseInit> {
  const origin = request.headers.get('origin');
  
  try {
    const config = getAuth0Config();
    const authHeader = request.headers.get('authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return addCorsHeaders({
        status: 401,
        jsonBody: {
          error: 'Unauthorized',
          message: 'No access token provided',
        },
      }, origin);
    }
    
    const accessToken = authHeader.substring(7);
    
    // Fetch user info from Auth0
    const userInfoResponse = await fetch(`https://${config.domain}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });
    
    if (!userInfoResponse.ok) {
      const status = userInfoResponse.status === 401 ? 401 : 500;
      return addCorsHeaders({
        status,
        jsonBody: {
          error: status === 401 ? 'Unauthorized' : 'Error',
          message: 'Failed to fetch user information',
        },
      }, origin);
    }
    
    const userInfo = await userInfoResponse.json();
    
    return addCorsHeaders({
      status: 200,
      jsonBody: userInfo,
    }, origin);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.error('Failed to fetch user info', error as Error);
    
    return addCorsHeaders({
      status: 500,
      jsonBody: {
        error: 'Error',
        message: 'Failed to fetch user information',
      },
    }, origin);
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

app.http('authMe', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'auth/me',
  handler: handleMe,
});





