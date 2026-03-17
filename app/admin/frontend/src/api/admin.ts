/**
 * Admin-specific API functions.
 */
import { api, setAccessToken } from './client';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

interface UserResponse {
  id: number;
  username?: string;
  email: string;
  is_staff: boolean;
  is_superuser: boolean;
}

interface AdminConfig {
  auth_type: 'django' | 'email';
}

export interface SchemaField {
  name: string;
  type: string;
  editable: boolean;
  required: boolean;
  options: string[] | null;
}

export interface ModelSchema {
  label: string;
  has_password_change: boolean;
  list_display: string[] | null;
  fields: SchemaField[];
}

export interface AppSchema {
  label: string;
  models: Record<string, ModelSchema>;
}

export interface SchemaResponse {
  apps: Record<string, AppSchema>;
}

interface PaginatedResponse {
  count: number;
  page: number;
  page_size: number;
  total_pages: number;
  results: Record<string, unknown>[];
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export async function login(
  credentials: Record<string, string>,
): Promise<TokenResponse> {
  const res = await api.postForm<TokenResponse>('/admin/login/', credentials);
  setAccessToken(res.access_token);
  return res;
}

export async function logout(): Promise<void> {
  try {
    await api.post('/auth/logout');
  } finally {
    setAccessToken(null);
  }
}

export async function fetchCurrentUser(): Promise<UserResponse> {
  return api.get<UserResponse>('/auth/users/me');
}

export async function changePassword(
  old_password: string,
  new_password: string,
): Promise<void> {
  await api.post('/auth/change-password', { old_password, new_password });
}

// ---------------------------------------------------------------------------
// Admin config
// ---------------------------------------------------------------------------

export async function fetchAdminConfig(): Promise<AdminConfig> {
  return api.get<AdminConfig>('/admin/config/');
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export async function fetchSchema(): Promise<SchemaResponse> {
  return api.get<SchemaResponse>('/admin/schema/');
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

export interface ListParams {
  page?: number;
  page_size?: number;
  search?: string;
  ordering?: string;
}

export async function fetchRecords(
  app: string,
  model: string,
  params: ListParams = {},
): Promise<PaginatedResponse> {
  const query = new URLSearchParams();
  if (params.page) query.set('page', String(params.page));
  if (params.page_size) query.set('page_size', String(params.page_size));
  if (params.search) query.set('search', params.search);
  if (params.ordering) query.set('ordering', params.ordering);
  const qs = query.toString();
  return api.get<PaginatedResponse>(`/admin/${app}/${model}/${qs ? `?${qs}` : ''}`);
}

export async function fetchRecord(
  app: string,
  model: string,
  id: number | string,
): Promise<Record<string, unknown>> {
  return api.get(`/admin/${app}/${model}/${id}/`);
}

export async function createRecord(
  app: string,
  model: string,
  data: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return api.post(`/admin/${app}/${model}/`, data);
}

export async function updateRecord(
  app: string,
  model: string,
  id: number | string,
  data: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return api.patch(`/admin/${app}/${model}/${id}/`, data);
}

export async function deleteRecord(
  app: string,
  model: string,
  id: number | string,
): Promise<void> {
  await api.delete(`/admin/${app}/${model}/${id}/`);
}

export async function bulkDeleteRecords(
  app: string,
  model: string,
  ids: number[],
): Promise<{ deleted: number }> {
  return api.post(`/admin/${app}/${model}/bulk-delete/`, { ids });
}

export async function adminSetPassword(
  app: string,
  model: string,
  id: number | string,
  new_password: string,
): Promise<{ message: string }> {
  return api.post(`/admin/${app}/${model}/${id}/set-password/`, { new_password });
}
