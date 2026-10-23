# TrustVault API and Route Documentation

## 1. Overview

TrustVault is a Flask web application for controlled document sharing, role-based authorization, and audit logging.

This document describes the intended route permissions. The actual routes, HTTP methods, and permissions must be compared with the submitted application's code before final submission.

## 2. Authentication

| Route | Purpose | Intended access |
|---|---|---|
| `/login` | Sign in | Public |
| `/logout` | End the current session | Authenticated users |
| `/` | Home page | As implemented |

## 3. Document Management

| Route | Purpose | Intended access |
|---|---|---|
| `/upload` | Upload a document | Authorized roles only |
| `/documents` | View owned documents | Owner or explicitly authorized roles |
| `/my-docs` | View the current user's documents | Authenticated users, subject to ownership checks |
| `/shared` | View documents shared with the current user | Authenticated users, subject to recipient checks |
| `/share/<document_id>` | Grant access to a document | Document owner or authorized administrator, according to policy |
| Document download route | Download a document | Owner or recipient with current permission |

**Note:** The exact download URL and supported HTTP methods must be copied from the actual application routes.

## 4. Administration and Audit

| Route | Purpose | Intended access |
|---|---|---|
| `/admin` | Administrative functions | Admin only, if implemented that way |
| `/admin/audit` | Review audit records | Authorized administrative roles |
| `/owner` | Owner-specific functions | Owner only |

These permissions describe the intended security policy, not independently verified route behavior.

## 5. Authorization Requirements

Every protected document operation should verify authorization on the server.

- A user must not gain access by changing a document identifier.
- A viewer must only access documents currently shared with them.
- Revoked access must no longer permit protected document operations.
- Users must not access owner-only or admin-only functions without the appropriate role.
- Audit records must be protected from unauthorized viewing or modification.
- Unauthorized requests should return an appropriate denial response.

## 6. Error Responses

| HTTP status | Meaning |
|---|---|
| `200 OK` | Request succeeded |
| `302 Found` | Redirect, commonly used by browser-based authentication |
| `400 Bad Request` | Invalid request |
| `401 Unauthorized` | Authentication required, where applicable |
| `403 Forbidden` | Request denied due to insufficient permission |
| `404 Not Found` | Resource not found |
| `413 Content Too Large` | Upload exceeds the configured limit |
| `500 Internal Server Error` | Unexpected server error |

The exact response depends on the route implementation and Flask configuration.

## 7. File Upload Security

The application should validate allowed file types and enforce a maximum upload size. Uploaded files should be stored privately and downloaded only after authorization checks.

## 8. Audit Events

Audit records should contain relevant details such as:

- Actor or username
- Action performed
- Target document, where applicable
- Timestamp
- Outcome, such as success or denial

Do not expose secrets or document contents in audit records.

## 9. Verification Before Submission

- [ ] Compare this document with every route in the actual application.
- [ ] Record the real HTTP methods for each route.
- [ ] Verify the access requirements against decorators and authorization checks.
- [ ] Confirm the exact document download endpoint.
- [ ] Run tests for allowed and denied roles.
- [ ] Remove any routes that do not exist from this documentation.
