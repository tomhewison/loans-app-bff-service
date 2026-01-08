import * as appInsights from 'applicationinsights';

/**
 * Application Insights Logger
 * 
 * Provides structured logging that integrates with Azure Application Insights.
 * Supports custom dimensions, metrics, and correlation tracking.
 */

// Initialize Application Insights if connection string is available
const connectionString = process.env.APPLICATIONINSIGHTS_CONNECTION_STRING;
let client: appInsights.TelemetryClient | null = null;

if (connectionString) {
  appInsights.setup(connectionString)
    .setAutoCollectRequests(true)
    .setAutoCollectPerformance(true, true)
    .setAutoCollectExceptions(true)
    .setAutoCollectDependencies(true)
    .setAutoCollectConsole(true, true)
    .setUseDiskRetryCaching(true)
    .setSendLiveMetrics(true)
    .setDistributedTracingMode(appInsights.DistributedTracingModes.AI_AND_W3C)
    .start();
  
  client = appInsights.defaultClient;
}

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error';

export type LogContext = {
  correlationId?: string;
  userId?: string;
  operation?: string;
  service?: string;
  [key: string]: string | number | boolean | undefined;
};

export type Logger = {
  trace: (message: string, context?: LogContext) => void;
  debug: (message: string, context?: LogContext) => void;
  info: (message: string, context?: LogContext) => void;
  warn: (message: string, context?: LogContext) => void;
  error: (message: string, error?: Error, context?: LogContext) => void;
  trackMetric: (name: string, value: number, context?: LogContext) => void;
  trackEvent: (name: string, context?: LogContext) => void;
  trackDependency: (
    name: string,
    target: string,
    duration: number,
    success: boolean,
    context?: LogContext
  ) => void;
  startOperation: (name: string, correlationId?: string) => OperationContext;
  flush: () => Promise<void>;
};

export type OperationContext = {
  correlationId: string;
  end: (success: boolean) => void;
  logger: Logger;
};

const SERVICE_NAME = 'bff-service';

/**
 * Converts LogContext to Application Insights custom dimensions
 */
function toCustomDimensions(context?: LogContext): Record<string, string> {
  if (!context) return { service: SERVICE_NAME };
  
  const dimensions: Record<string, string> = { service: SERVICE_NAME };
  for (const [key, value] of Object.entries(context)) {
    if (value !== undefined) {
      dimensions[key] = String(value);
    }
  }
  return dimensions;
}

/**
 * Gets severity level string for Application Insights
 */
function getSeverityLevel(level: LogLevel): string {
  switch (level) {
    case 'trace':
      return 'Verbose';
    case 'debug':
      return 'Verbose';
    case 'info':
      return 'Information';
    case 'warn':
      return 'Warning';
    case 'error':
      return 'Error';
    default:
      return 'Information';
  }
}

/**
 * Logs a message at the specified level
 */
function log(level: LogLevel, message: string, context?: LogContext): void {
  const timestamp = new Date().toISOString();
  const logPrefix = `[${timestamp}] [${level.toUpperCase()}] [${SERVICE_NAME}]`;
  const contextStr = context ? ` ${JSON.stringify(context)}` : '';
  
  // Console logging (always available)
  const consoleMessage = `${logPrefix} ${message}${contextStr}`;
  switch (level) {
    case 'trace':
    case 'debug':
      console.debug(consoleMessage);
      break;
    case 'info':
      console.info(consoleMessage);
      break;
    case 'warn':
      console.warn(consoleMessage);
      break;
    case 'error':
      console.error(consoleMessage);
      break;
  }

  // Application Insights logging
  if (client) {
    client.trackTrace({
      message,
      severity: getSeverityLevel(level),
      properties: toCustomDimensions(context),
    });
  }
}

/**
 * Logs an error with stack trace
 */
function logError(message: string, error?: Error, context?: LogContext): void {
  const errorContext: LogContext = {
    ...context,
    errorMessage: error?.message,
    errorStack: error?.stack,
  };
  
  log('error', message, errorContext);
  
  // Track exception in Application Insights
  if (client && error) {
    client.trackException({
      exception: error,
      properties: toCustomDimensions(context),
    });
  }
}

/**
 * Tracks a custom metric
 */
function trackMetric(name: string, value: number, context?: LogContext): void {
  console.info(`[METRIC] ${SERVICE_NAME} - ${name}: ${value}`);
  
  if (client) {
    client.trackMetric({
      name,
      value,
      properties: toCustomDimensions(context),
    });
  }
}

/**
 * Tracks a custom event
 */
function trackEvent(name: string, context?: LogContext): void {
  console.info(`[EVENT] ${SERVICE_NAME} - ${name}`);
  
  if (client) {
    client.trackEvent({
      name,
      properties: toCustomDimensions(context),
    });
  }
}

/**
 * Tracks a dependency call (e.g., database, external API)
 */
function trackDependency(
  name: string,
  target: string,
  duration: number,
  success: boolean,
  context?: LogContext
): void {
  const status = success ? 'success' : 'failure';
  console.info(`[DEPENDENCY] ${SERVICE_NAME} - ${name} to ${target}: ${status} (${duration}ms)`);
  
  if (client) {
    client.trackDependency({
      dependencyTypeName: 'HTTP',
      name,
      target,
      duration,
      success,
      resultCode: success ? 200 : 500,
      data: context?.operation as string,
      properties: toCustomDimensions(context),
    });
  }
}

/**
 * Starts a new operation context for correlation
 */
function startOperation(name: string, correlationId?: string): OperationContext {
  const opCorrelationId = correlationId || generateCorrelationId();
  const startTime = Date.now();
  
  // Create a scoped logger for this operation
  const scopedContext: LogContext = {
    correlationId: opCorrelationId,
    operation: name,
  };
  
  const scopedLogger: Logger = {
    trace: (msg, ctx) => log('trace', msg, { ...scopedContext, ...ctx }),
    debug: (msg, ctx) => log('debug', msg, { ...scopedContext, ...ctx }),
    info: (msg, ctx) => log('info', msg, { ...scopedContext, ...ctx }),
    warn: (msg, ctx) => log('warn', msg, { ...scopedContext, ...ctx }),
    error: (msg, err, ctx) => logError(msg, err, { ...scopedContext, ...ctx }),
    trackMetric: (n, v, ctx) => trackMetric(n, v, { ...scopedContext, ...ctx }),
    trackEvent: (n, ctx) => trackEvent(n, { ...scopedContext, ...ctx }),
    trackDependency: (n, t, d, s, ctx) => trackDependency(n, t, d, s, { ...scopedContext, ...ctx }),
    startOperation: (n, c) => startOperation(n, c || opCorrelationId),
    flush: () => flush(),
  };
  
  scopedLogger.info(`Starting operation: ${name}`);
  
  return {
    correlationId: opCorrelationId,
    end: (success: boolean) => {
      const duration = Date.now() - startTime;
      scopedLogger.info(`Operation ${name} completed`, {
        success,
        durationMs: duration,
      });
      
      if (client) {
        client.trackRequest({
          name,
          url: name,
          duration,
          resultCode: success ? '200' : '500',
          success,
          properties: toCustomDimensions(scopedContext),
        });
      }
    },
    logger: scopedLogger,
  };
}

/**
 * Generates a unique correlation ID
 */
function generateCorrelationId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * Flushes all pending telemetry
 */
async function flush(): Promise<void> {
  if (client) {
    return new Promise((resolve) => {
      client!.flush();
      // Give time for telemetry to be sent
      setTimeout(() => resolve(), 100);
    });
  }
}

/**
 * Main logger instance
 */
export const logger: Logger = {
  trace: (message, context) => log('trace', message, context),
  debug: (message, context) => log('debug', message, context),
  info: (message, context) => log('info', message, context),
  warn: (message, context) => log('warn', message, context),
  error: (message, error, context) => logError(message, error, context),
  trackMetric,
  trackEvent,
  trackDependency,
  startOperation,
  flush,
};

/**
 * Creates a child logger with preset context
 */
export function createLogger(baseContext: LogContext): Logger {
  return {
    trace: (msg, ctx) => log('trace', msg, { ...baseContext, ...ctx }),
    debug: (msg, ctx) => log('debug', msg, { ...baseContext, ...ctx }),
    info: (msg, ctx) => log('info', msg, { ...baseContext, ...ctx }),
    warn: (msg, ctx) => log('warn', msg, { ...baseContext, ...ctx }),
    error: (msg, err, ctx) => logError(msg, err, { ...baseContext, ...ctx }),
    trackMetric: (n, v, ctx) => trackMetric(n, v, { ...baseContext, ...ctx }),
    trackEvent: (n, ctx) => trackEvent(n, { ...baseContext, ...ctx }),
    trackDependency: (n, t, d, s, ctx) => trackDependency(n, t, d, s, { ...baseContext, ...ctx }),
    startOperation: (n, c) => startOperation(n, c),
    flush: () => flush(),
  };
}

export default logger;





