# Data Model & API Contract

> Defines the entities, REST endpoints, and request/response shapes for the Djast Admin Panel.
> Based on the demo analysis (`demo_djast_admin_analysis.md`) and Djast auth docs.

---

## 1. Authentication (Djast Auth Module)

The admin panel uses Djast's built-in JWT auth. No signup — admin users are created via backend.

**Base path:** `/api/v1/auth`

### 1.1 Endpoints Used by the Admin Panel

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/token` | POST | No | Login (username + password) → access token + refresh cookie |
| `/refresh` | POST | No | Rotate refresh token → new access token |
| `/logout` | POST | Yes | Revoke current session |
| `/users/me` | GET | Yes | Get authenticated user details (for top bar display) |
| `/change-password` | POST | Yes | Update password (revokes all sessions) |

### 1.2 Auth Flow

```
1. User submits login form
2. POST /api/v1/auth/token  (username + password, form-encoded)
   → 200: { access_token, token_type: "bearer", expires_in: 1800 }
   → Sets refresh_token as HttpOnly cookie
   → 401: Invalid credentials
   → 429: Rate limited (5/min)

3. Store access_token in memory (NOT localStorage)
4. All subsequent requests: Authorization: Bearer {access_token}

5. On 401 response → POST /api/v1/auth/refresh (cookie-based)
   → 200: New access_token
   → 401: Refresh expired → redirect to login

6. Logout → POST /api/v1/auth/logout → clear token from memory
```

### 1.3 Auth Request/Response Shapes

```
POST /api/v1/auth/token
Content-Type: application/x-www-form-urlencoded

username=admin&password=Secret1!xx

→ 200
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 1800
}

→ 401
{ "detail": "Invalid credentials" }

→ 429
{ "detail": "Rate limit exceeded" }
```

```
GET /api/v1/auth/users/me
Authorization: Bearer {access_token}

→ 200
{
  "id": 1,
  "username": "admin",
  "email": "admin@example.com",
  "first_name": "Admin",
  "last_name": "",
  "is_active": true,
  "date_joined": "2024-01-15T10:30:00Z"
}
```

```
POST /api/v1/auth/change-password
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "old_password": "Secret1!xx",
  "new_password": "NewPass1!yy"
}

→ 200 { "message": "Password changed successfully" }
→ 400 { "detail": "Invalid old password" }
```

### 1.4 Auth Error Handling

| Status | Meaning | Frontend Action |
|--------|---------|-----------------|
| 401 | Token expired/invalid | Attempt refresh; if refresh fails → redirect to login |
| 403 | Forbidden | Show error toast |
| 429 | Rate limited | Show "Too many attempts, try again later" |

### 1.5 Security Notes

- Access token: 30 min TTL, stored in JS memory only
- Refresh token: 7 day TTL, HttpOnly cookie, path-scoped to auth endpoints
- Account lockout: 5 failed attempts → 5 min lockout
- Password requirements: 8-100 chars, uppercase, lowercase, digit, special char

---

## 2. Entities

### 2.1 Admin Schema Registry

The admin panel needs to know which apps/models exist and how to render them. This comes from a schema endpoint.

```
GET /api/v1/admin/schema/

→ 200
{
  "apps": {
    "users": {
      "label": "Users",
      "icon": "users",
      "models": {
        "user": {
          "label": "User",
          "fields": [
            { "name": "id",          "type": "integer", "editable": false, "required": false },
            { "name": "username",     "type": "string",  "editable": true,  "required": true  },
            { "name": "email",        "type": "email",   "editable": true,  "required": true  },
            { "name": "first_name",   "type": "string",  "editable": true,  "required": false },
            { "name": "last_name",    "type": "string",  "editable": true,  "required": false },
            { "name": "is_active",    "type": "boolean", "editable": true,  "required": false },
            { "name": "date_joined",  "type": "datetime","editable": false, "required": false }
          ]
        },
        "group": { ... }
      }
    },
    "blog": { ... },
    "store": { ... }
  }
}
```

### 2.2 Entity Definitions

#### User (`users.user`)

| Field | Type | Editable | Required | Notes |
|-------|------|----------|----------|-------|
| `id` | integer | no | — | Auto PK |
| `username` | string | yes | yes | Unique |
| `email` | email | yes | yes | Unique |
| `first_name` | string | yes | no | |
| `last_name` | string | yes | no | |
| `is_active` | boolean | yes | no | Default: true |
| `date_joined` | datetime | no | — | Server-set |

#### Group (`users.group`)

| Field | Type | Editable | Required | Notes |
|-------|------|----------|----------|-------|
| `id` | integer | no | — | Auto PK |
| `name` | string | yes | yes | Unique |
| `permissions_count` | integer | no | — | Computed |
| `created_at` | datetime | no | — | Server-set |

#### Post (`blog.post`)

| Field | Type | Editable | Required | Notes |
|-------|------|----------|----------|-------|
| `id` | integer | no | — | Auto PK |
| `title` | string | yes | yes | |
| `slug` | string | yes | yes | Derived from title |
| `author` | string | yes | yes | |
| `status` | select | yes | yes | Options: `Draft`, `Published`, `Archived` |
| `category` | string | yes | no | |
| `created_at` | datetime | no | — | Server-set |
| `updated_at` | datetime | no | — | Server-set |

#### Category (`blog.category`)

| Field | Type | Editable | Required | Notes |
|-------|------|----------|----------|-------|
| `id` | integer | no | — | Auto PK |
| `name` | string | yes | yes | |
| `slug` | string | yes | yes | Derived from name |
| `post_count` | integer | no | — | Computed |

#### Tag (`blog.tag`)

| Field | Type | Editable | Required | Notes |
|-------|------|----------|----------|-------|
| `id` | integer | no | — | Auto PK |
| `name` | string | yes | yes | |
| `slug` | string | yes | yes | Derived from name |

#### Product (`store.product`)

| Field | Type | Editable | Required | Notes |
|-------|------|----------|----------|-------|
| `id` | integer | no | — | Auto PK |
| `name` | string | yes | yes | |
| `sku` | string | yes | yes | Unique, pattern: `SKU-XXXX` |
| `price` | decimal | yes | yes | Display: `€{value}` |
| `stock` | integer | yes | yes | Min: 0 |
| `status` | select | yes | yes | Options: `Active`, `Out of Stock`, `Discontinued` |
| `created_at` | datetime | no | — | Server-set |

#### Order (`store.order`)

| Field | Type | Editable | Required | Notes |
|-------|------|----------|----------|-------|
| `id` | integer | no | — | Auto PK |
| `order_number` | string | no | — | Server-generated, pattern: `ORD-XXXX` |
| `customer` | string | yes | yes | |
| `total` | decimal | no | — | Display: `€{value}` |
| `status` | select | yes | yes | Options: `Pending`, `Processing`, `Shipped`, `Delivered`, `Cancelled` |
| `created_at` | datetime | no | — | Server-set |

### 2.3 Field Type System

| Type | JSON type | Input widget | Table display |
|------|-----------|-------------|---------------|
| `integer` | number | `<input type="number">` | Plain number |
| `string` | string | `<input type="text">` | Plain text |
| `email` | string | `<input type="email">` | Plain text |
| `boolean` | boolean | Toggle/checkbox | Badge (Yes/No) |
| `decimal` | string | `<input type="number" step="0.01">` | Formatted (e.g. `€12.50`) |
| `select` | string | `<select>` | Colored badge |
| `datetime` | string (ISO 8601) | Read-only text | Formatted `YYYY-MM-DD HH:MM` |

### 2.4 Status Badge Colors

| Value | Color |
|-------|-------|
| Published, Active, Delivered, Shipped | green |
| Draft, Pending, Processing | yellow |
| Archived, Discontinued, Cancelled | gray |
| Out of Stock | red |

---

## 3. REST API Endpoints

**Base path:** `/api/v1/admin`

All admin endpoints require `Authorization: Bearer {access_token}`.

### 3.1 Schema

```
GET /api/v1/admin/schema/
→ 200: Full app/model/field registry (see §2.1)
```

### 3.2 Generic CRUD

The API follows a generic pattern: `/api/v1/admin/{app}/{model}/`

#### List Records

```
GET /api/v1/admin/{app}/{model}/
Authorization: Bearer {token}

Query params:
  page      integer   default: 1        Page number
  page_size integer   default: 100      Records per page (max: 100)
  search    string    optional          Full-text search across all string fields
  ordering  string    optional          Field name; prefix with - for descending (e.g. -created_at)

→ 200
{
  "count": 247,
  "page": 1,
  "page_size": 100,
  "total_pages": 3,
  "results": [
    {
      "id": 1,
      "username": "alice_m",
      "email": "alice_m@example.com",
      "first_name": "Alice",
      "last_name": "Morgan",
      "is_active": true,
      "date_joined": "2024-03-15T10:30:00Z"
    },
    ...
  ]
}
```

#### Get Single Record

```
GET /api/v1/admin/{app}/{model}/{id}/
Authorization: Bearer {token}

→ 200
{
  "id": 1,
  "username": "alice_m",
  ...
}

→ 404 { "detail": "Not found" }
```

#### Create Record

```
POST /api/v1/admin/{app}/{model}/
Authorization: Bearer {token}
Content-Type: application/json

{
  "username": "bob_k",
  "email": "bob_k@example.com",
  "first_name": "Bob",
  "last_name": "Klein",
  "is_active": true
}

→ 201
{
  "id": 42,
  "username": "bob_k",
  "email": "bob_k@example.com",
  "first_name": "Bob",
  "last_name": "Klein",
  "is_active": true,
  "date_joined": "2026-03-15T14:22:00Z"
}

→ 400 { "detail": { "email": ["This field must be unique."] } }
```

#### Update Record

```
PATCH /api/v1/admin/{app}/{model}/{id}/
Authorization: Bearer {token}
Content-Type: application/json

{
  "first_name": "Robert"
}

→ 200
{
  "id": 42,
  "username": "bob_k",
  "email": "bob_k@example.com",
  "first_name": "Robert",
  ...
}

→ 404 { "detail": "Not found" }
→ 400 { "detail": { "email": ["This field must be unique."] } }
```

#### Delete Record

```
DELETE /api/v1/admin/{app}/{model}/{id}/
Authorization: Bearer {token}

→ 204 (no body)
→ 404 { "detail": "Not found" }
```

#### Bulk Delete

```
POST /api/v1/admin/{app}/{model}/bulk-delete/
Authorization: Bearer {token}
Content-Type: application/json

{
  "ids": [1, 2, 3]
}

→ 200 { "deleted": 3 }
→ 400 { "detail": "ids field is required" }
```

### 3.3 Endpoint Summary Table

| Action | Method | Path | Body | Response |
|--------|--------|------|------|----------|
| Get schema | GET | `/admin/schema/` | — | App/model registry |
| List | GET | `/admin/{app}/{model}/` | — | Paginated results |
| Detail | GET | `/admin/{app}/{model}/{id}/` | — | Single record |
| Create | POST | `/admin/{app}/{model}/` | JSON fields | Created record (201) |
| Update | PATCH | `/admin/{app}/{model}/{id}/` | JSON fields (partial) | Updated record |
| Delete | DELETE | `/admin/{app}/{model}/{id}/` | — | 204 |
| Bulk delete | POST | `/admin/{app}/{model}/bulk-delete/` | `{ ids: [...] }` | `{ deleted: N }` |
| Login | POST | `/auth/token` | form-encoded | `{ access_token, ... }` |
| Refresh | POST | `/auth/refresh` | cookie | `{ access_token, ... }` |
| Logout | POST | `/auth/logout` | — | 200 |
| Current user | GET | `/auth/users/me` | — | User object |
| Change password | POST | `/auth/change-password` | JSON | 200 |

---

## 4. Error Response Format

All errors follow a consistent shape:

```
{
  "detail": "Error message"          // string for simple errors
}

// or for validation errors:
{
  "detail": {
    "field_name": ["Error message"]  // field-level errors
  }
}
```

| Status | Meaning |
|--------|---------|
| 400 | Validation error (missing/invalid fields, uniqueness violation) |
| 401 | Not authenticated / token expired |
| 403 | Forbidden |
| 404 | Record not found |
| 429 | Rate limited |
| 500 | Server error |

---

## 5. Frontend-Backend Contract Notes

### 5.1 Pagination
- Server-side, 100 records per page (matching project spec)
- Response includes `count`, `page`, `page_size`, `total_pages` for frontend pagination controls

### 5.2 Search
- Server-side full-text search via `?search=` query param
- Searches across all string-type fields of the model
- Frontend should debounce (300ms) before sending

### 5.3 Sorting
- Server-side via `?ordering=` query param
- Single field sorting; prefix `-` for descending
- Default: `-id` (newest first)

### 5.4 Schema-Driven UI
- Frontend fetches schema once on load, caches it
- Sidebar, forms, table columns, and validation are all derived from the schema
- No hardcoded model definitions in frontend code

### 5.5 Optimistic vs Pessimistic Updates
- **List operations** (delete, bulk delete): Pessimistic — wait for server confirmation, then refresh list
- **Detail save**: Pessimistic — wait for server response, show field-level validation errors if 400
- **Navigation**: Immediate — no loading gate between screens

### 5.6 Token Management
- Access token stored in memory (JS variable/React state), never localStorage
- Refresh token handled automatically via HttpOnly cookie
- Auth interceptor: on 401 → attempt silent refresh → retry original request → if refresh fails → redirect to login
