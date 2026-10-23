# TrustVault API Documentation

## 1. Overview

TrustVault is a Flask-based secure document-sharing application. Its routes support authentication, document management, sharing, permission revocation, and audit review.

**Live deployment:** http://3.91.27.213/  
**Repository:** https://github.com/BattuMonishaNandini10/TrustVault

**Security note:** The live deployment uses HTTP, not verified HTTPS. Do not upload real sensitive documents.

## 2. Authentication and Roles

TrustVault uses authenticated user sessions and role-based authorization.

| Role | Intended access |
|---|---|
| Owner | Manage owned documents and their sharing permissions |
| Viewer | Access documents explicitly shared with them, subject to current permissions |
| Admin | Access authorized administrative functions and audit records |

A user's role alone should not grant access to every document. Document-level authorization must be checked for each protected operation.

## 3. Route Reference

The following routes are based on the project routes identified during development. Confirm the HTTP methods and behavior against `app.py`.

| Route | Expected access | Purpose |
|---|---|---|
| `/` | Public or authenticated, depending on implementation | Home page |
| `/login` | Public | Sign in |
| `/logout` | Authenticated | Sign out |
| `/upload` | Authorized users | Upload a document |
| `/documents` | Authorized users | View documents the user is allowed to manage |
| `/share/<document_id>` | Authorized document owner | Grant document access |
| `/shared` | Authenticated users | View documents shared with the current user |
| `/admin/audit` | Admin or other explicitly authorized roles | Review audit records |

**Important:** This table is not a substitute for checking the actual route decorators and methods. Add any edit, download, delete, search, permission-revocation, and other routes that exist in the application.

## 4. Authorization Requirements

Every sensitive request should enforce authorization on the server.

- **Authentication:** Unauthenticated users must not access protected operations.
- **Document access:** The server must check ownership or an active sharing permission before returning document contents.
- **Download:** A direct download request must perform the same access checks as the document listing page.
- **Editing and deletion:** Only users explicitly authorized for the requested action may modify or delete a document.
- **Sharing:** Only an authorized document owner or other explicitly permitted role may grant access.
- **Revocation:** Once permission is revoked, subsequent requests must deny access unless another valid permission exists.
- **Administration:** Administrative routes must enforce the required role server-side.
- **Audit records:** Access to audit information must be restricted to authorized users.

## 5. Error Responses

Actual responses depend on the route and Flask error handlers. Verify these behaviors during testing.

| Status | Meaning |
|---|---|
| `200 OK` | Request succeeded |
| `302 Found` | Redirect, commonly used in login flows |
| `400 Bad Request` | Invalid request |
| `401 Unauthorized` | Authentication is required or invalid |
| `403 Forbidden` | The user is not permitted to perform the action |
| `404 Not Found` | Resource or route was not found |
| `413 Content Too Large` | Upload exceeds the configured size limit |
| `500 Internal Server Error` | Unexpected server-side failure |

Where appropriate, the application may return a generic not-found response instead of revealing whether an inaccessible document exists.

## 6. Security Testing

Test the routes with separate owner, viewer, and admin accounts.

1. Verify that unauthenticated requests cannot access protected documents.
2. Verify that a viewer cannot access a document that has not been shared with them.
3. Attempt direct downloads by changing document IDs.
4. Verify that revoking permission blocks subsequent document requests.
5. Verify that unauthorized edit and delete requests are denied.
6. Verify that only authorized roles can access administrative audit routes.
7. Verify that denied attempts are recorded where audit logging is implemented.

Run automated tests against an isolated test database rather than the production database.

## 7. Limitations

This document must be reconciled with the final application before submission. Route methods, request parameters, response formats, and error handling should be documented only after checking the implementation.

The existence of a route does not prove that its authorization checks are correct. Automated and manual tests should confirm the actual behavior.
