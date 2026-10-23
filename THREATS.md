# TrustVault Threat Model

## 1. Purpose

TrustVault is designed to share documents securely between authorized users. The main security objective is to prevent unauthorized document access and maintain useful records of document activity.

This document identifies important threats, intended mitigations, and checks required before claiming that a threat is addressed.

## 2. Assets to Protect

- Uploaded documents and their contents
- User accounts and password hashes
- Document ownership and sharing permissions
- Session cookies and application secrets
- Audit records
- Document integrity hashes
- Database contents and deployment configuration

## 3. Security Assumptions

- Users may attempt to access documents belonging to other users.
- An authenticated user may attempt to exceed their assigned role.
- Sharing links and document identifiers may be guessed or modified.
- Uploaded files may be malicious or malformed.
- Access permissions may be revoked after being granted.
- Administrators and deployment environments must also be protected.
- Application logs and database files may contain sensitive information.

## 4. Threats and Mitigations

| ID | Threat | Intended mitigation | Verification required |
|---|---|---|---|
| T1 | Insecure direct object reference (IDOR) | Check the current user's permission for every document request | Test access using another user's document ID |
| T2 | Unauthorized route access | Apply server-side authentication and role checks | Test protected routes for each role |
| T3 | Access after revocation | Check current permissions when a document is requested | Revoke access and retry the request |
| T4 | Sharing with the wrong user | Validate the intended recipient and show clear sharing information | Test recipient validation and grants |
| T5 | Privilege escalation | Enforce role permissions on the server, not only in the interface | Attempt restricted actions as a viewer |
| T6 | Missing audit events | Record relevant successful and denied security actions | Verify expected audit entries |
| T7 | Audit record tampering | Restrict access to audit data and separate administrative permissions | Test unauthorized audit modification |
| T8 | Malicious file upload | Validate file types and sizes; treat uploaded files as untrusted | Test disallowed extensions and oversized files |
| T9 | Direct storage exposure | Store private files outside public static directories | Attempt unauthenticated direct file access |
| T10 | Metadata disclosure | Restrict document listings and search results to authorized records | Test listing and search as another user |
| T11 | Session misuse | Use secure session settings and proper logout/session handling | Test session expiry and cookie settings |
| T12 | Cross-site request forgery (CSRF) | Protect state-changing requests with CSRF defenses | Test unauthorized cross-origin requests |
| T13 | SQL injection | Use parameterized database queries | Review queries and test hostile input |
| T14 | Permission race conditions | Recheck permissions at access time and handle concurrent changes carefully | Test access around revocation |
| T15 | Secrets or private data in Git | Exclude secrets, private uploads, and sensitive database files from the repository | Review current files and Git history |

## 5. Security Principles

### Least privilege
Each role should have only the permissions needed for its intended tasks.

### Server-side authorization
Hiding a button or link is not a security control. Protected actions must enforce authorization on the server.

### Default deny
Requests should be rejected unless the application can establish that the user is authorized.

### Auditability
Security-relevant actions should produce meaningful audit records, including the actor, action, time, target, and outcome where applicable.

### Private storage
Uploaded documents must not become publicly accessible merely because a user knows a filename or URL.

## 6. Verification Plan

Before submission, verify the following:

- [ ] An unauthenticated user cannot access protected documents.
- [ ] A viewer cannot access an unshared document by changing its ID.
- [ ] Revoked permissions no longer allow document access.
- [ ] Viewers cannot perform owner-only or admin-only actions.
- [ ] Unauthorized audit access is denied.
- [ ] Invalid and oversized uploads are rejected.
- [ ] Audit events are recorded for relevant actions.
- [ ] Automated security tests use an isolated test database.
- [ ] The repository contains no secrets or confidential user documents.
- [ ] The deployed application has been tested using the documented demo roles.

## 7. Residual Risks

The threat model does not prove that the application is secure. Remaining risks depend on the actual implementation, deployment configuration, testing coverage, and operational controls.

Controls must be marked verified only after the corresponding code, test results, or deployment settings have been reviewed.

## 8. Incident Response

If a credential is exposed, revoke or rotate it immediately. If unauthorized document access is suspected, preserve relevant audit records, restrict affected access, investigate the incident, and rotate any potentially compromised credentials.

## 9. Review Status

This document is a threat assessment and verification plan. It must be updated to reflect the actual application, observed test results, and any unresolved vulnerabilities before final submission.
