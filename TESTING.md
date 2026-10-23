# TrustVault — Testing

## 1. Purpose

TrustVault uses automated tests and manual checks to verify authentication, role-based access control, document permissions, and audit-related security behavior.

## 2. Automated Security Tests

The security test suite is located in `tests/test_security.py`.

The tests should use an isolated temporary SQLite database so that testing does not modify the application's actual database.

Important security scenarios to test:

- Unauthenticated users cannot access protected document routes.
- A user cannot access another user's private documents without permission.
- Shared documents are accessible only to authorized recipients.
- Revoked sharing permissions no longer allow access.
- Viewer, owner, and admin permissions are enforced correctly.
- Unauthorized access attempts are handled safely.
- Audit events are recorded for security-relevant actions.

## 3. Manual Verification Checklist

- [ ] Log in and log out successfully.
- [ ] Upload a test document.
- [ ] Confirm the document owner can see their document.
- [ ] Share a document with an authorized test account.
- [ ] Confirm the recipient can access the shared document.
- [ ] Revoke access and verify the recipient can no longer access it.
- [ ] Verify unauthorized users cannot access protected routes.
- [ ] Verify only authorized roles can view audit logs.
- [ ] Check that document integrity verification detects modified file content, where implemented.

## 4. Evidence and Results

Record the actual test command, date, results, and any failures before submission.

Do not mark a test as passed unless it has been executed and its result verified.

| Test area | Result |
|---|---|
| Authentication | Record actual result |
| Document authorization | Record actual result |
| Sharing and revocation | Record actual result |
| Role-based access | Record actual result |
| Audit access control | Record actual result |
| File integrity | Record actual result |

## 5. Limitations

Testing provides evidence for the scenarios covered; it does not prove that the application is free of security vulnerabilities. Additional testing is needed before production use.
