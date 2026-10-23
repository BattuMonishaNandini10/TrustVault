# TrustVault — Five-Minute Demo Script

## 0:00–0:30 — Introduction

Introduce TrustVault as a secure document-sharing application designed to control who can access documents and provide an audit trail of important actions.

Explain the main problem: a document should not be accessible to the wrong person, and access permissions should be revocable.

## 0:30–1:15 — Authentication and Roles

Demonstrate logging in with the prepared demo accounts for owner, viewer, and admin.

Explain that each role has different permissions. Show only behavior that has been verified in the running application.

Do not show real passwords, personal documents, or secret keys.

## 1:15–2:15 — Document Upload and Sharing

Log in as the owner and upload a harmless sample document.

Show the document in the owner's document list. Share it with the designated viewer account and explain how access is granted.

## 2:15–3:00 — Access Control and Revocation

Log in as the viewer and demonstrate access to the shared document.

If verified, show that the viewer cannot access a document belonging to another user without permission.

Return to the owner account, revoke the viewer's permission, and demonstrate that access is denied afterward.

## 3:00–4:00 — Audit Trail and Integrity

Show the audit page using an authorized account.

Explain which actions are recorded and how the audit trail helps investigate document access.

If file-integrity verification is implemented and tested, demonstrate it using a harmless test file. Do not claim that a feature works unless verified.

## 4:00–4:35 — Automated Security Tests

Show the security test file and the actual test results.

Explain how tests use an isolated database and verify authorization behavior. Report the real result; do not claim tests passed without running them.

## 4:35–5:00 — Architecture and Conclusion

Briefly describe the technologies actually used, including Python, Flask, SQLite, and the AWS services confirmed in the deployment.

Conclude by summarizing the implemented controls, known limitations, and possible future improvements.

## Recording Checklist

- [ ] Use harmless sample documents and demo accounts.
- [ ] Verify the application and demo accounts work before recording.
- [ ] Confirm the live URL is reachable.
- [ ] Hide passwords, personal information, secret keys, and private files.
- [ ] Show real application behavior and actual test output.
- [ ] Keep the recording within five minutes.
- [ ] Review the video before submitting it.
