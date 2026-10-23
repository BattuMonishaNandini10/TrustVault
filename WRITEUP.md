# TrustVault — Project Write-up

## 1. Project Overview

TrustVault is a secure document-sharing application developed for the Snovasys Fresher Hiring Challenge 2026.

The goal is to let authorized users share documents while preventing unauthorized access and maintaining an audit trail of relevant actions.

The project focuses on three security requirements:

1. Only authorized users should be able to access a document.
2. Sharing permissions should be controllable and revocable.
3. Document-related activity should be auditable.

## 2. Architecture

The intended application architecture consists of:

- **User interface:** HTML templates rendered by Flask.
- **Application layer:** Python and Flask routes for authentication, document management, sharing, and audit functionality.
- **Authentication:** Flask-Login and password hashing.
- **Authorization:** Role-based and document-level permission checks.
- **Database:** SQLite for application records.
- **File storage:** Private document storage.
- **Integrity checking:** SHA-256 hashes for checking file integrity.
- **Deployment:** AWS EC2, subject to verification of the live configuration.

The browser sends requests to the Flask application. The application authenticates the user, checks permissions, performs authorized operations, and returns the appropriate response.

## 3. Security Design Decisions

### Authentication

Users must authenticate before accessing protected functionality. Passwords should be stored as secure hashes rather than plaintext.

### Authorization

Authorization must be enforced on the server. A user interface that hides restricted links is not sufficient.

### Document sharing

Document access should depend on the current user's ownership or valid sharing permissions. Revoked access must be rejected by subsequent protected requests.

### Audit trail

Relevant security events should record the actor, action, target, timestamp, and outcome where applicable.

### File integrity

SHA-256 can be used to compare a stored file hash with the hash calculated from retrieved file contents. This detects mismatches but does not, by itself, prove who uploaded a file or prevent every form of tampering.

## 4. AWS Deployment

The application has been prepared for deployment on an AWS EC2 instance.

The final submission should identify only the services actually used and verified.

| Component | Purpose |
|---|---|
| AWS EC2 | Host the application server |
| Gunicorn | Serve the Flask application as a production WSGI process, if confirmed in the deployed configuration |
| Nginx | Act as a reverse proxy, if confirmed in the deployed configuration |
| SQLite | Store application data on the configured host |

No AWS service should be described as integrated unless the implementation and configuration demonstrate that integration.

The final deployment documentation must include the verified live URL, setup steps, required environment variables, and any relevant network configuration.

## 5. Testing Strategy

The testing strategy should cover:

- Login and logout
- Owner, viewer, and admin permissions
- Access to owned documents
- Access to documents shared with a recipient
- Denial of access to unrelated users
- Revocation of sharing permissions
- Restricted administrative routes
- Audit logging
- Invalid and oversized uploads
- File integrity verification

Automated tests should use an isolated test database and must detect the removal of the relevant authorization checks.

Test results must be reported only after the tests have actually been run.

## 6. AI Assistance

AI assistance was used for project planning, understanding Flask functionality, debugging errors, developing test ideas, and preparing documentation.

AI output was treated as a starting point rather than a guarantee of correctness. Suggested code and security controls required review and testing.

The AI prompt log should document actual prompts, useful outputs, specific issues discovered, fixes applied, and links to the relevant commits.

## 7. Challenges and Lessons Learned

The development process involved understanding route permissions, debugging application errors, testing the owner/viewer/admin workflows, and reviewing access-control behavior.

A key lesson is that successful login does not mean a user is authorized to access every document. Authorization must be checked for each protected operation.

Another lesson is that a security feature is not proven merely because it appears in the interface. It must be verified using appropriate tests.

## 8. Known Limitations

The final submission must explicitly identify:

- Security controls that have not been tested
- Automated tests that have not passed
- Deployment settings that remain unverified
- Any unfinished features
- Any limitations in audit integrity or operational monitoring

These limitations should be updated after the final repository and deployment review.

## 9. Conclusion

TrustVault aims to demonstrate secure document sharing through authentication, least-privilege authorization, revocable permissions, file integrity checks, and auditability.

The quality of the final submission depends on matching the documentation to the actual implementation and providing evidence that the security controls work.

## Challenge

Snovasys Fresher Hiring Challenge 2026
