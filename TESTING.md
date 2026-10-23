# TrustVault — Testing Guide

## 1. Purpose

TrustVault uses automated and manual testing to check document authorization, role restrictions, sharing, permission revocation, file handling, and audit behavior.

Security tests are important because a document must remain protected even when a user bypasses the normal interface and sends a direct request.

## 2. Test Environment

Run tests in a local development environment with Python and the project's dependencies installed.

From the project directory, activate the virtual environment and install the dependencies listed in `requirements.txt`, if present.

```bash
python -m pytest -q
```

Run the security test module separately:

```bash
python -m pytest -q tests/test_security.py
```

**Important:** Run tests against an isolated temporary database. Do not run destructive tests against production data or a database containing real documents.

## 3. Main Security Test Areas

### Authentication

- Unauthenticated users cannot access protected operations.
- Valid demo users can log in.
- Logging out prevents further use of the logged-out session as an authenticated user.

### Role-based access control

- Viewers cannot perform owner-only operations.
- Viewers cannot access administrator-only pages.
- Owners cannot access administrator-only operations unless explicitly authorized.
- Administrative routes enforce their role restrictions on the server.

### Document-level authorization

- A user cannot read another user's private document without permission.
- Changing a document ID in a URL does not bypass authorization.
- Direct download requests enforce the same permission checks as normal document views.
- Unauthorized users cannot edit or delete protected documents.

### Sharing and revocation

- An authorized owner can grant document access to a named recipient.
- A user without permission cannot access the document.
- Revoking a recipient's permission blocks subsequent requests.
- Permission changes are checked on the server rather than trusted from the browser.

### File validation and integrity

- Unsupported file extensions are rejected.
- Oversized uploads are rejected.
- Invalid file requests are handled safely.
- File-integrity checks detect a mismatch when an expected SHA-256 hash is available and verified by the application.

### Audit logging

- Important successful operations generate audit records where implemented.
- Denied access attempts are recorded where implemented.
- Unauthorized users cannot access restricted audit views.
- Audit records include useful information about the actor, action, document, outcome, and time where supported by the schema.

## 4. Manual Role Testing

Use separate demo accounts for owner, viewer, and administrator roles.

| Test | Expected behavior |
|---|---|
| Viewer requests an unshared document | Access denied |
| Viewer downloads a shared document | Allowed only while permission remains valid |
| Viewer attempts an owner-only operation | Access denied |
| Viewer attempts an administrator-only route | Access denied |
| Owner grants access to a recipient | Permission is saved and recorded where implemented |
| Owner revokes access | Later requests from that recipient are denied |
| Unauthenticated user requests a protected file | Authentication or access denial |
| Unauthorized user opens the audit page | Access denied |

Record the actual response and audit result for each test. Do not treat a hidden button or missing link as proof that a server-side security check works.

## 5. Automated Test Results

Earlier development runs reported these results:

- Security test module: **75 passed**.
- Full test suite: **195 passed**.

These are historical results, not confirmation that the latest repository version still passes. Re-run both commands after the final changes and replace the figures with the actual output before submission.

```bash
python -m pytest -q tests/test_security.py
python -m pytest -q
```

If a test fails, investigate the failure and record the correction. Do not remove a meaningful security test merely to obtain a passing result.

## 6. Test Quality and Limitations

A useful authorization test should fail if the relevant authorization check is removed. For example, a test for an unshared document should make a request as a user who has no permission and verify that the response does not disclose the document.

Test coverage should include direct requests, not just ordinary browser navigation. Passing automated tests provides evidence about the tested cases, but does not prove that every possible attack has been prevented.

## 7. Final Verification Checklist

Before submission:

- [ ] Run the complete test suite on the final code.
- [ ] Run the security test module independently.
- [ ] Verify owner, viewer, and admin behavior with separate accounts.
- [ ] Test direct document access and download requests.
- [ ] Test permission revocation.
- [ ] Check denied attempts and audit records.
- [ ] Confirm tests use an isolated database.
- [ ] Record the actual final test output.
- [ ] Ensure no credentials or sensitive test files are committed.
