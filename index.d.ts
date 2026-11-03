export interface Frame {
  fn: string;
  file: string;
  line: number;
  col: number;
}

export type BeaconEnv = 'prod' | 'preview';
export type BeaconSource = 'server' | 'client';

export interface BeaconEvent {
  v: 1;
  ts: string;
  product: string;
  env: BeaconEnv;
  release_sha: string;
  route: string;
  source: BeaconSource;
  name: string;
  message: string;
  signature: string;
  frames: Frame[];
}

export interface BeaconContextConfig {
  product: string;
  env: BeaconEnv;
  releaseSha?: string;
}

export interface BeaconContext {
  product: string;
  env: BeaconEnv;
  release_sha: string;
}

export interface LimitConfig {
  capacity: number;
  refillPerSec: number;
}

export const MAX_FRAMES: number;
export const MAX_MESSAGE_LENGTH: number;
export const MAX_ROUTE_LENGTH: number;
export const ENVIRONMENTS: readonly BeaconEnv[];
export const SOURCES: readonly BeaconSource[];
export const EVENT_VERSION: 1;
export const EVENT_SCHEMA: Readonly<Record<string, unknown>>;
export const SERVICE_LABEL: 'error-beacon';
export const OVERFLOW_LABEL: '[other]';
export const DEFAULT_MAX_BODY_BYTES: number;

export function scrubMessage(input: unknown, options?: { maxLength?: number }): string;
export function scrubPath(path: unknown): string;
export function scrubStack(stack: unknown): Frame[];
export function normalizeRoute(input: unknown): string;
export function matchRoute(input: unknown, templates: readonly string[]): string;
export function normalizeFileForSignature(file: string): string;
export function computeSignature(name: string, frames: readonly { fn: string; file: string }[], messageTemplate: string): string;

export function resolveContext(config: BeaconContextConfig): BeaconContext;
export function buildEvent(
  context: BeaconContext,
  error: { name?: unknown; message?: unknown; stack?: unknown },
  meta?: { route?: unknown; source?: BeaconSource; now?: Date },
): BeaconEvent;
export function buildEventFromThrown(
  context: BeaconContext,
  thrown: unknown,
  meta?: { route?: unknown; source?: BeaconSource; now?: Date },
): BeaconEvent;
export function eventFromClientPayload(context: BeaconContext, raw: unknown, now?: Date): BeaconEvent | null;
export function validateEvent(event: unknown): event is BeaconEvent;

export class TokenBucket {
  constructor(options: LimitConfig & { now?: () => number });
  take(): boolean;
}
export class KeyedLimiter {
  constructor(options: LimitConfig & { maxKeys?: number; now?: () => number });
  take(key: string): boolean;
}
export class LabelBudget {
  constructor(max: number);
  admit(value: string): string;
}

export interface PushResult {
  ok: boolean;
  status?: number;
  reason?: 'invalid-event' | 'not-configured' | 'loki-rejected' | 'network';
}
export interface LokiForwarderConfig {
  lokiUrl?: string;
  accessClientId?: string;
  accessClientSecret?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  maxRoutes?: number;
  maxSignatures?: number;
  onError?: (reason: string) => void;
}
export function buildPushBody(event: BeaconEvent, labelOverrides?: { route?: string; signature?: string }): string;
export function createLokiForwarder(config?: LokiForwarderConfig): { push(event: BeaconEvent): Promise<PushResult> };

export interface ErrorsHandlerOptions {
  context: BeaconContextConfig;
  forward: (event: BeaconEvent) => Promise<unknown>;
  routeTemplates?: readonly string[];
  allowedOrigins?: readonly string[];
  maxBodyBytes?: number;
  rate?: LimitConfig;
  perSignature?: LimitConfig;
  waitUntil?: (promise: Promise<unknown>) => void;
  now?: () => number;
}
export function createErrorsHandler(options: ErrorsHandlerOptions): (request: Request) => Promise<Response>;

export interface Reporter {
  report(thrown: unknown, meta?: { route?: unknown; source?: BeaconSource }): Promise<void>;
}
export function createReporter(options: {
  context: BeaconContextConfig;
  forward: (event: BeaconEvent) => Promise<unknown>;
  perSignature?: LimitConfig;
  now?: () => number;
}): Reporter;
export function sveltekitHandleError(reporter: Reporter, inner?: (input: any) => any): (input: any) => Promise<any>;
export function nextOnRequestError(reporter: Reporter): (error: unknown, request?: { path?: string }, context?: { routePath?: string }) => Promise<void>;
export function astroErrorMiddleware(reporter: Reporter): (context: any, next: () => Promise<Response>) => Promise<Response>;
