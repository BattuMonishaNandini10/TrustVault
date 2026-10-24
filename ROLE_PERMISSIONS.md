# TrustVault role and document-permission model

TrustVault has three account roles. Server-side authorization is checked on
each protected request; hiding a control in the interface is not a permission
check.

| Capability | Administrator | Owner | Viewer |
|---|---|---|---|
| Browse and search | All documents | Owned documents and documents actively shared with them | Documents actively shared with them |
| Upload | Yes | Yes | No |
| Read, preview, and download | All documents | Owned documents and documents actively shared with them | Only actively shared documents |
| Edit document metadata (name/category) | Any document | Owned documents | Only documents shared with `edit` permission |
| Delete a document | Any document | Owned documents | No |
| Grant or revoke document access | Any document | Owned documents | No |
| View full audit trail and security dashboard | Yes | No | No |
| Manage user account status | Yes | No | No |

## Document grants

Owners and administrators can grant access to a named existing account:

- **Read** permits viewing, PDF/DOCX preview, and downloading.
- **Edit** permits the same read operations plus changing the document name and
  category. It does not permit deleting the document or managing its grants.
- Grants can have an optional UTC expiry. Expired grants no longer authorize
  document access, and owners/administrators can revoke grants at any time.

An owner is authorized for documents they own. An administrator's role is an
explicit system-wide authorization; administrators do not need a separate
document grant. Every other account needs an active document-level grant.

## Upload validation and audit

Uploads are limited to 10 MB per request, must use an allowed file extension
(PDF, TXT, PNG, JPG/JPEG, DOCX, or CSV), must have a non-empty filename and
content, and are stored under a sanitized filename. Uploads also receive a
SHA-256 integrity hash.

The audit trail records document uploads, downloads, views, metadata edits,
deletions, grants, revocations, and denied access attempts. Only administrators
can view the full audit trail and security dashboard.
