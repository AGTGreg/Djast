# Djast Admin Panel — Demo Analysis

> Deep analysis of `demo_djast_admin.html` to inform the transition from static demo to real app.

---

## 1. UI Screens & States

### 1.1 Login Screen (`#login-screen`)

| State | Trigger | Visual |
|-------|---------|--------|
| Default | Page load | Email + password inputs, "Sign In" button |
| Validation error (empty fields) | Submit with empty fields | Red error banner: "Please fill in all fields." |
| Validation error (bad creds) | N/A (demo accepts anything) | Red error banner: "Invalid email or password." (exists in HTML but never triggered) |
| Loading | Submit with valid fields | Button text hidden, spinner shown, button disabled for 800ms |
| Password visible | Click eye icon | Input type toggles `password` ↔ `text`, icon toggles `eye` ↔ `eye-off` |

**Missing states (need to implement):**
- Real JWT authentication (POST to `/api/auth/login`)
- Token storage (localStorage/cookie)
- Token refresh flow
- "Session expired" redirect back to login
- Rate limiting / lockout feedback

### 1.2 List Screen (`#list-screen`)

| State | Trigger | Visual |
|-------|---------|--------|
| Default | Click model in sidebar | Table with paginated records, title "{Model} List" |
| Empty (no records) | Search yields 0 results or model has no data | "No records found" with inbox icon, table header hidden |
| Search active | Type in search bar | Client-side filter across all field values, page resets to 1 |
| Sorted | Click column header | Sort icon (chevron-up/down) appears on active column, toggles asc/desc |
| Rows selected | Check row checkboxes | Bulk actions dropdown appears with count badge |
| Select all (page) | Check header checkbox | All rows on current page selected; unchecking deselects page rows only |
| Bulk actions open | Click "Actions" button | Dropdown with "Delete selected" |
| Bulk delete confirm | Click "Delete selected" | Delete confirmation modal opens |
| After bulk delete | Confirm in modal | Records removed from in-memory store, toast, list re-renders |

**Missing states (need to implement):**
- Loading/skeleton state while fetching from API
- Server-side search (currently client-side full-text across all fields)
- Server-side sorting
- Server-side pagination (currently `pageSize: 10`, project spec says 100)
- Error state (API failure)
- Debounced search input
- URL-based routing (back/forward browser navigation)

### 1.3 Detail Screen (`#detail-screen`)

| State | Trigger | Visual |
|-------|---------|--------|
| Edit existing | Click row in list | Form pre-filled with record data, title "{Model} #{id}" |
| Add new | Click "Add New" button | Empty form with only editable fields, title "Add {Model}", delete button hidden |
| Save (edit) | Click "Save" | Updates in-memory record, toast, navigates to list |
| Save (new) | Click "Save" | Creates record in-memory (prepended), toast, navigates to list |
| Delete single | Click "Delete" button | Delete confirmation modal opens |
| After delete | Confirm in modal | Record removed, toast, navigates to list |

**Missing states (need to implement):**
- Form validation (required fields, email format, etc.)
- Loading state while saving/deleting
- Error state (API failure on save/delete)
- Dirty form detection ("unsaved changes" warning)
- Optimistic vs. pessimistic update strategy

### 1.4 Persistent Components

#### Sidebar (`#sidebar`)
| State | Trigger | Visual |
|-------|---------|--------|
| Desktop | `lg:` breakpoint | Fixed left, always visible, 256px wide |
| Mobile closed | Default on mobile | Off-screen (`-translate-x-full`) |
| Mobile open | Hamburger button click | Slides in, dark overlay behind |
| Active model | Navigate to a model | Sidebar link gets `active` class (green highlight) |

#### Top Bar
| State | Trigger | Visual |
|-------|---------|--------|
| Default | Any authenticated screen | Breadcrumb + user menu button |
| Breadcrumb (list) | On list screen | `{App} > {Model}` (model is bold, not clickable) |
| Breadcrumb (detail) | On detail screen | `{App} > {Model} > #{id}` or `Add new` (model is clickable link) |
| User menu open | Click avatar/name | Dropdown: "Change Password", "Logout" |
| User menu closed | Click outside | Dropdown hidden |

#### Change Password Modal (`#change-password-modal`)
| State | Trigger | Visual |
|-------|---------|--------|
| Open | User menu → "Change Password" | Modal with 3 password fields + Cancel/Save |
| Save | Click "Save" | Closes modal, shows success toast (no validation) |

**Missing states:** Real password validation, current password verification, password strength requirements, error handling.

#### Delete Confirmation Modal (`#delete-confirm-action-group`)
| State | Trigger | Visual |
|-------|---------|--------|
| Open | Delete button (single or bulk) | Warning icon, count of records, Cancel/Delete buttons |
| Confirm | Click "Delete" | Closes modal, executes delete callback |
| Cancel | Click "Cancel" | Closes modal, no action |

#### Toast Notifications (`#toast-container`)
| Type | Duration | Visual |
|------|----------|--------|
| Success | 3 seconds | Green background, slides up from bottom-right |
| Error | 3 seconds | Red background, slides up from bottom-right |

---

## 2. Mock Data — Shapes & Data Model

### 2.1 Apps & Models Registry

```
Apps:
  Users → [User, Group]
  Blog  → [Post, Category, Tag]
  Store → [Product, Order]
```

Each app has: `icon` (string), `models` (dict of model configs).

### 2.2 Model Schemas

#### User
| Field | Type | Editable | Notes |
|-------|------|----------|-------|
| `id` | number | no | Auto-increment |
| `username` | text | yes | Pattern: `{first}_{last_initial}` + optional number |
| `email` | email | yes | Pattern: `{username}@example.com` |
| `first_name` | text | yes | From 20-name pool |
| `last_name` | text | yes | From 20-name pool |
| `is_active` | boolean | yes | ~85% true |
| `date_joined` | datetime | no | Range: 2022–2025 |

Record count: **100**

#### Group
| Field | Type | Editable | Notes |
|-------|------|----------|-------|
| `id` | number | no | Auto-increment |
| `name` | text | yes | From 8-group pool |
| `permissions_count` | number | no | Random 1–20 |
| `created_at` | datetime | no | Range: 2022–2025 |

Record count: **8**

#### Post
| Field | Type | Editable | Notes |
|-------|------|----------|-------|
| `id` | number | no | Auto-increment |
| `title` | text | yes | From 20-title pool, suffixed with `(n)` for duplicates |
| `slug` | text | yes | Derived from title |
| `author` | text | yes | `{firstName} {lastName}` |
| `status` | select | yes | Options: `Draft`, `Published`, `Archived` (weighted: ~60% Published) |
| `category` | text | yes | From 8-category pool |
| `created_at` | datetime | no | Range: 2023–2025 |
| `updated_at` | datetime | no | `created_at` + up to 90 days |

Record count: **100**

#### Category
| Field | Type | Editable | Notes |
|-------|------|----------|-------|
| `id` | number | no | Auto-increment |
| `name` | text | yes | From 8-category pool |
| `slug` | text | yes | Derived from name |
| `post_count` | number | no | Random 1–30 |

Record count: **8**

#### Tag
| Field | Type | Editable | Notes |
|-------|------|----------|-------|
| `id` | number | no | Auto-increment |
| `name` | text | yes | From 15-tag pool |
| `slug` | text | yes | Derived from name |

Record count: **15**

#### Product
| Field | Type | Editable | Notes |
|-------|------|----------|-------|
| `id` | number | no | Auto-increment |
| `name` | text | yes | From 20-product pool, suffixed with `v{n}` for duplicates |
| `sku` | text | yes | Pattern: `SKU-{0001}` |
| `price` | number | yes | Random 5.00–205.00, displayed as €{value} |
| `stock` | number | yes | Random 0–500 |
| `status` | select | yes | Options: `Active`, `Out of Stock`, `Discontinued` (weighted: ~60% Active) |
| `created_at` | datetime | no | Range: 2023–2025 |

Record count: **100**

#### Order
| Field | Type | Editable | Notes |
|-------|------|----------|-------|
| `id` | number | no | Auto-increment |
| `order_number` | text | no | Pattern: `ORD-{1000+i}` |
| `customer` | text | yes | `{firstName} {lastName}` |
| `total` | number | no | Random 10.00–510.00, displayed as €{value} |
| `status` | select | yes | Options: `Pending`, `Processing`, `Shipped`, `Delivered`, `Cancelled` |
| `created_at` | datetime | no | Range: 2024–2025 |

Record count: **100**

### 2.3 Field Type System

| Type | Input widget | Display in table | Display in form |
|------|-------------|-----------------|-----------------|
| `number` | `<input type="number">` | Plain number, or `€{value}` if decimal string | Same |
| `text` | `<input type="text">` | Plain text | Same |
| `email` | `<input type="email">` | Plain text | Same |
| `boolean` | Checkbox + Yes/No label | Badge (green=Yes, gray=No) | Checkbox + colored label |
| `select` | `<select>` with options | Colored badge (status-dependent) | Same |
| `datetime` | `<input type="text">` (readonly) | Formatted string `YYYY-MM-DD HH:MM` | Same |

### 2.4 Status Badge Color Mapping

| Value | Badge class |
|-------|-------------|
| Published, Active, Delivered, Shipped | `badge-green` |
| Draft, Pending, Processing | `badge-yellow` |
| Archived, Discontinued, Cancelled | `badge-gray` |
| Out of Stock | `badge-red` |

---

## 3. Dynamic Behaviors → React State

### 3.1 Global App State

```typescript
interface AppState {
  // Auth
  loggedIn: boolean;
  // Navigation
  currentScreen: 'login' | 'list' | 'detail';
  currentApp: string | null;
  currentModel: string | null;
  // List screen
  currentRecord: Record<string, any> | null;
  isNewRecord: boolean;
  selectedRows: Set<number>;
  searchQuery: string;
  sortField: string | null;
  sortDir: 'asc' | 'desc';
  currentPage: number;
  pageSize: number;  // 10 in demo, 100 in spec
  // UI toggles
  sidebarOpen: boolean;
  userMenuOpen: boolean;
}
```

### 3.2 Behavior Inventory

| Behavior | Current implementation | React equivalent |
|----------|----------------------|------------------|
| Screen switching | `navigate()` adds/removes `.active` class | React Router or state-based conditional rendering |
| Sidebar toggle (mobile) | CSS translate + overlay toggle | `useState(sidebarOpen)` |
| User menu dropdown | Toggle hidden class | `useState(userMenuOpen)` + click-outside hook |
| Bulk actions dropdown | Toggle hidden class | `useState(bulkActionsOpen)` |
| Search filtering | Client-side `Array.filter` on input event | `useState(searchQuery)` + debounce + API call |
| Column sorting | Client-side `Array.sort` on header click | `useState({sortField, sortDir})` + API call |
| Pagination | Client-side slice of array | `useState(currentPage)` + API call with offset/limit |
| Row selection | `Set<number>` in state, checkbox onChange | `useState(selectedRows: Set<number>)` |
| Select all (page) | Header checkbox toggles all page rows | Derived from page data + selectedRows |
| Form field rendering | DOM creation from field config | Dynamic form component from model schema |
| Modal open/close | Toggle `.visible` class | `useState(modalOpen)` or modal context |
| Toast notifications | DOM append + setTimeout remove | Toast context/provider with auto-dismiss |
| Password visibility | Toggle input type + icon swap | `useState(showPassword)` |
| Loading spinner (login) | Toggle hidden on button children | `useState(isLoading)` |

---

## 4. Fake Interactions → Real Backend Requirements

### 4.1 Authentication

| Fake behavior | Real requirement |
|---------------|-----------------|
| Any email/password accepted | `POST /api/auth/login` → JWT `{access, refresh}` |
| No token stored | Store access token (memory/cookie), refresh token (httpOnly cookie) |
| No session management | Token refresh on 401, logout clears tokens |
| "Password changed successfully" (always) | `POST /api/auth/change-password` with old/new password validation |
| Hardcoded "Admin" username in top bar | Fetch from JWT claims or `GET /api/auth/me` |

### 4.2 Data Fetching

| Fake behavior | Real requirement |
|---------------|-----------------|
| Data generated in-browser from `generate()` functions | `GET /api/{app}/{model}/` → paginated list |
| Client-side search | `GET /api/{app}/{model}/?search={query}` |
| Client-side sort | `GET /api/{app}/{model}/?ordering={field}` or `-{field}` |
| Client-side pagination (pageSize=10) | `GET /api/{app}/{model}/?page={n}&page_size=100` |
| `dataStore` object | Server database |

### 4.3 CRUD Operations

| Fake behavior | Real requirement |
|---------------|-----------------|
| Save new: `dataStore[key].unshift(newRecord)` | `POST /api/{app}/{model}/` with form data |
| Save edit: mutate `data[index]` in place | `PUT/PATCH /api/{app}/{model}/{id}/` |
| Delete single: `filter()` from dataStore | `DELETE /api/{app}/{model}/{id}/` |
| Bulk delete: `filter()` from dataStore | `POST /api/{app}/{model}/bulk-delete/` with `{ids: [...]}` |
| Auto-increment IDs | Server-assigned IDs |
| Auto-generated `created_at`, `updated_at` | Server-set timestamps |

### 4.4 Model Registry / Schema

| Fake behavior | Real requirement |
|---------------|-----------------|
| Hardcoded `mockApps` object with field definitions | `GET /api/schema/` → dynamic app/model/field registry |
| Field types and editability hardcoded | Schema should define: field name, type, editable, required, options, display config |
| Record counts hardcoded per model | Actual record counts from database |
| Status badge color mapping hardcoded | Either from schema metadata or frontend config |

---

## 5. Styleguide & Design Tokens

### 5.1 Color Palette

| Token | Value | Usage |
|-------|-------|-------|
| `brand-green` | `#2ed573` | Primary actions, active states, success |
| `brand-yellow` | `#eccc68` | Warning states |
| `brand-gray` | `#f1f2f6` | Backgrounds, secondary buttons |
| `brand-charcoal` | `#2f3542` | Text, sidebar background |
| `brand-red` | `#ff4757` | Danger actions, error states |
| `brand-blue` | `#3742fa` | (Defined but unused in demo) |

### 5.2 Border Radius

| Token | Value | Usage |
|-------|-------|-------|
| `btn` | 16px | Buttons |
| `card` | 16px | Cards, modals, toasts |
| `input` | 16px | Form inputs, sidebar links |

### 5.3 Typography

- **Font family:** Google Sans, system-ui, sans-serif
- **Font weights:** 400 (normal), 600 (semibold), 700 (bold)

### 5.4 Component Classes

| Class | Purpose |
|-------|---------|
| `.btn`, `.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-ghost` | Button variants |
| `.card` | White container with border + shadow |
| `.form-field`, `.form-field-readonly`, `.form-field-icon` | Input styling |
| `.form-label` | Label styling |
| `.table-header`, `.table-cell`, `.table-row` | Table styling |
| `.sidebar-link`, `.sidebar-link.active`, `.sidebar-app-header` | Sidebar nav |
| `.badge`, `.badge-green`, `.badge-yellow`, `.badge-red`, `.badge-gray` | Status badges |
| `.toast`, `.toast-success`, `.toast-error` | Toast notifications |
| `.modal-overlay`, `.modal-panel` | Modal system |
| `.skeleton` | Loading skeleton |
| `.screen`, `.screen.active` | Screen visibility toggling |

### 5.5 External Dependencies

| Library | CDN | Purpose |
|---------|-----|---------|
| Tailwind CSS | `cdn.tailwindcss.com` | Utility CSS framework |
| Google Sans | Google Fonts | Primary typeface |
| Lucide Icons | `unpkg.com/lucide@latest` | Icon system (used via `data-lucide` attributes) |

---

## 6. Summary: Key Gaps Between Demo and Real App

1. **No real authentication** — JWT login/refresh/logout cycle needs implementation
2. **No API layer** — All data is client-side generated; need REST API with pagination, search, sort
3. **No dynamic schema** — App/model/field definitions are hardcoded; need schema endpoint
4. **No form validation** — Save always succeeds; need field-level validation (required, format, uniqueness)
5. **No loading states** — Only login has a spinner; list/detail need skeleton/loading UI
6. **No error handling** — No API error feedback, no retry logic, no offline state
7. **No URL routing** — Navigation is purely state-driven; browser back/forward won't work
8. **Page size mismatch** — Demo uses 10 per page, spec says 100
9. **No real user identity** — "Admin" is hardcoded; should come from auth context
10. **Skeleton loader defined but unused** — `.skeleton` CSS class exists but no skeleton UI is rendered anywhere
