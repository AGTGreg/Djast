/**
 * API client with JWT auth + automatic refresh.
 *
 * Access token is kept in memory (never localStorage).
 * Refresh uses the HttpOnly cookie set by the auth backend.
 */

const API_PREFIX = '/api/v1';

let accessToken: string | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export class AuthError extends Error {
  constructor(message = 'Authentication failed') {
    super(message);
    this.name = 'AuthError';
  }
}

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown;
}

async function request<T = unknown>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, headers: extraHeaders, ...rest } = options;

  const headers: Record<string, string> = {
    ...(extraHeaders as Record<string, string>),
  };

  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  const isRawBody = body instanceof FormData || body instanceof URLSearchParams;

  if (body !== undefined && !isRawBody) {
    headers['Content-Type'] = 'application/json';
  }

  const encodeBody = (b: unknown) =>
    b instanceof FormData || b instanceof URLSearchParams
      ? b
      : b !== undefined
        ? JSON.stringify(b)
        : undefined;

  const res = await fetch(`${API_PREFIX}${path}`, {
    ...rest,
    headers,
    credentials: 'include',
    body: encodeBody(body),
  });

  // Try refresh on 401
  if (res.status === 401 && accessToken) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      headers['Authorization'] = `Bearer ${accessToken}`;
      const retry = await fetch(`${API_PREFIX}${path}`, {
        ...rest,
        headers,
        credentials: 'include',
        body: encodeBody(body),
      });
      return handleResponse(retry);
    }
    accessToken = null;
    throw new AuthError();
  }

  return handleResponse(res);
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (res.status === 204) return undefined as T;

  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    const err = new Error(detail.detail || res.statusText);
    (err as any).status = res.status;
    (err as any).detail = detail.detail;
    throw err;
  }

  return res.json();
}

async function tryRefresh(): Promise<boolean> {
  try {
    const res = await fetch(`${API_PREFIX}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
    });
    if (!res.ok) return false;
    const data = await res.json();
    accessToken = data.access_token;
    return true;
  } catch {
    return false;
  }
}

export const api = {
  get: <T = unknown>(path: string) => request<T>(path),

  post: <T = unknown>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body }),

  patch: <T = unknown>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PATCH', body }),

  delete: <T = unknown>(path: string) =>
    request<T>(path, { method: 'DELETE' }),

  postForm: <T = unknown>(path: string, data: Record<string, string>) => {
    const formData = new URLSearchParams(data);
    return request<T>(path, {
      method: 'POST',
      body: formData,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
  },
};
