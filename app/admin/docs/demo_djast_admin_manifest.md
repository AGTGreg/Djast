# Djast Admin Panel — Demo Manifest

> Source of truth for all screens and action groups in `demo_djast_admin.html`.

## Mock Apps & Models

| App       | Models              |
|-----------|---------------------|
| Users     | User, Group         |
| Blog      | Post, Category, Tag |
| Store     | Product, Order      |

---

## Screens

| Screen (id)      | Purpose                          | Key Components                                                                 | Action Groups                    | Interactions                                                        | Mock Data                                      |
|------------------|----------------------------------|--------------------------------------------------------------------------------|----------------------------------|---------------------------------------------------------------------|-------------------------------------------------|
| `login-screen`   | JWT authentication               | Logo/branding, email input, password input, submit button                      | —                                | Form validation, simulated login, error states                      | —                                               |
| `list-screen`    | Browse model records             | Data table, pagination, search bar, sort controls, row checkboxes, "Add New" btn | `bulk-actions-action-group`      | Search/filter, sort asc/desc, select rows, paginate, nav to detail  | 100+ realistic records (names, dates, statuses) |
| `detail-screen`  | View/edit a single record (or add new) | Form with editable + read-only fields, Save/Delete buttons                     | `delete-confirm-action-group`    | Edit fields, save changes, delete record                            | Pre-filled form data matching list records      |

---

## Action Groups

| Action Group (id)               | Parent Screen  | Components                                      | Interactions                                    |
|---------------------------------|----------------|--------------------------------------------------|------------------------------------------------|
| `bulk-actions-action-group`     | `list-screen`  | Dropdown with "Delete selected" option           | Select action, confirm, simulate bulk delete    |
| `delete-confirm-action-group`   | `detail-screen`| Confirmation modal with cancel/confirm buttons   | Confirm or cancel single record deletion        |

---

## Persistent Components

| Component               | Description                                                                                     |
|--------------------------|-------------------------------------------------------------------------------------------------|
| **Sidebar**              | Collapsible. Shows apps with nested model lists. Click model → `list-screen`. Open on desktop, hidden on mobile. |
| **Top bar**              | Breadcrumb (current location), user menu (Change Password, Logout).                            |
| **Change Password modal**| Triggered from user menu. Fields: old password, new password, confirm password.                 |
| **Toast notifications**  | Success/error feedback for all CRUD actions.                                                    |

---

## Styleguide Reference

See `docs/styleguide.md` for theme spec (fonts, palette, radius, shadows, layout).
