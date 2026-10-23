# TrustVault — Threat Model

## 1. Project Overview

TrustVault is a Python Flask web application for securely uploading, organizing, sharing, and accessing documents. It uses role-based access control, document-level permissions, permission revocation, and audit logging.

The main security objective is to ensure that users can access only the documents and actions they are authorized to use, and that important activity is recorded for review.

**Deployment:** http://3.91.27.213/  
**Source code:** https://github.com/BattuMonishaNandini10/TrustVault

**Important deployment note:** The live URL uses HTTP. Traffic is not protected by HTTPS, so credentials and document contents may be exposed in transit. Do not upload real sensitive documents to this deployment.

## 2. Assets to Protect

| Asset | Why it matters |
|---|---|
| User accounts and passwords | Prevent account takeover and unauthorized access |
| Uploaded documents | Protect confidentiality and integrity |
| Document permissions | Ensure only authorized users can access shared files |
| Permission and ownership records | Prevent unauthorized sharing or changes |
| Audit logs | Help investigate access and security incidents |
| Application configuration and secrets | Prevent unauthorized access to the application and its services |
| AWS resources and credentials | Prevent unauthorized cloud access and data exposure |

## 3. Threat Actors

Potential threat actors include:

- An authenticated user attempting to access another user's documents.
- A viewer attempting to perform owner or administrator actions.
- A former recipient attempting to access a document after permission revocation.
- An unauthenticated visitor attempting to access protected routes or files.
- An attacker submitting malicious, oversized, or incorrectly formatted uploads.
- A user attempting to manipulate document identifiers, URLs, or request parameters.
- An attacker who obtains credentials, application secrets, or access to the server.
- A malicious or compromised administrator who misuses privileged access.

## 4. Main Threats and Mitigations

### Threat 1: Unauthorized document access

**Risk:** A user changes a document ID in a URL or sends a direct request to download another user's document.

**Potential impact:** Confidential documents may be disclosed.

**Mitigations:**
- Require authentication for protected operations.
- Check document ownership or explicit sharing permissions on the server.
- Apply authorization checks to document access and download routes.
- Test unauthorized access using different demo accounts.

**Residual risk:** A missing authorization check in any route could expose documents. Every route that reads, downloads, edits, deletes, or shares a document must be checked and tested.

### Threat 2: Privilege escalation between roles

**Risk:** A viewer attempts to perform owner or administrator operations by directly requesting a protected URL.

**Potential impact:** Unauthorized document management, permission changes, or access to audit records.

**Mitigations:**
- Use server-side role checks for privileged routes.
- Restrict administrative functions to authorized roles.
- Test direct requests as owner, viewer, and administrator accounts.

**Residual risk:** Role checks may be inconsistent across routes unless the complete route set is reviewed and tested.

### Threat 3: Unauthorized sharing or permission changes

**Risk:** A user grants access to a document they do not own, changes another user's permissions, or shares a document with an unintended recipient.

**Potential impact:** Unauthorized disclosure or loss of control over documents.

**Mitigations:**
- Verify the acting user's authority before changing permissions.
- Associate permissions with individual documents and recipients.
- Restrict permission grants and revocations to authorized users.
- Record permission changes in the audit log.

**Residual risk:** Incorrect database relationships or missing checks could still allow unintended sharing.

### Threat 4: Access after permission revocation

**Risk:** A former recipient continues accessing a document after their permission is revoked.

**Potential impact:** Continued unauthorized access.

**Mitigations:**
- Check current permissions when a document is requested.
- Revoke the corresponding document-sharing permission.
- Test access again after revocation, including direct download requests.

**Residual risk:** Revocation cannot undo a file that was already downloaded or copied. Cached copies and previously disclosed content may remain outside the application's control.

### Threat 5: Malicious file uploads

**Risk:** An attacker uploads a file with a misleading extension, an unsupported format, or an excessive size.

**Potential impact:** Storage exhaustion, exposure to malicious content, or possible exploitation of software that processes uploaded files.

**Mitigations:**
- Restrict allowed file extensions.
- Enforce an upload-size limit.
- Store uploaded files separately from application templates and source code.
- Avoid trusting the submitted filename as a safe storage path.

**Residual risk:** Extension checks alone do not establish that a file's actual contents are safe. Content validation, malware scanning, and safe handling of downloaded files require additional review.

### Threat 6: Document tampering or corruption

**Risk:** A stored file is altered or corrupted without the application detecting the change.

**Potential impact:** Users may receive modified or damaged documents.

**Mitigations:**
- Use SHA-256 hashes to check file integrity where implemented.
- Compare the stored expected hash with the hash of the retrieved file.
- Record detected integrity failures in the audit log where implemented.

**Residual risk:** A hash check detects changes only when the expected hash is trustworthy and the check is actually performed. SHA-256 alone does not prevent tampering, and it does not make audit logs tamper-proof.

### Threat 7: Missing or misleading audit records

**Risk:** Important actions or denied access attempts are not logged, or someone modifies or deletes the records.

**Potential impact:** Investigations become incomplete or unreliable.

**Mitigations:**
- Record important activities such as uploads, downloads, document changes, deletions, and permission changes where implemented.
- Record denied operations where implemented.
- Restrict access to administrative audit views.

**Residual risk:** Application-level logs may be incomplete or modifiable by someone with sufficient database or server access. Independent, tamper-resistant audit storage is not claimed unless separately implemented and verified.

### Threat 8: Credential theft and weak session security

**Risk:** An attacker obtains a user's password or steals a session.

**Potential impact:** Unauthorized access under that user's identity.

**Mitigations:**
- Use password hashing rather than storing plaintext passwords.
- Protect authenticated routes.
- Keep application secrets out of publicly committed source code.

**Residual risk:** Password hashing does not prevent phishing, weak passwords, session theft, or compromised credentials. HTTPS is not currently verified for the public deployment, making traffic interception a significant risk.

### Threat 9: Exposure of AWS resources or secrets

**Risk:** AWS credentials, overly permissive IAM policies, public storage settings, or exposed application secrets allow unauthorized cloud access.

**Potential impact:** Document disclosure, resource misuse, or unexpected costs.

**Mitigations:**
- Use narrowly scoped IAM permissions.
- Keep credentials and secrets out of Git.
- Review S3 bucket access policies and public-access settings.
- Review CloudWatch logs for accidental exposure of sensitive information.

**Residual risk:** The actual AWS configuration must be checked in the AWS Console. The use of AWS services alone does not guarantee secure configuration.

### Threat 10: Denial of service

**Risk:** Repeated requests or oversized uploads consume server resources.

**Potential impact:** The application becomes slow or unavailable.

**Mitigations:**
- Enforce an upload-size limit.
- Validate incoming requests.
- Monitor server health and application errors.

**Residual risk:** Rate limiting, resource quotas, and comprehensive abuse monitoring may require additional implementation and verification.

## 5. Security Testing Plan

The following tests should be run against an isolated test database and, where appropriate, the deployed application:

- Verify that unauthenticated users cannot access protected documents.
- Verify that a viewer cannot access documents without permission.
- Verify that a viewer cannot access owner-only or administrator-only routes.
- Verify that document permissions are checked on direct download requests.
- Verify that revoking permission blocks subsequent requests.
- Verify that unauthorized users cannot edit or delete another user's documents.
- Verify that upload extension and size restrictions work.
- Verify that audit records are generated for important allowed and denied actions.
- Verify that integrity checks detect changes to stored files.
- Verify that secrets and sensitive document contents are not accidentally exposed in logs or the public repository.

Automated tests should use a separate temporary database so that tests cannot damage real application data.

## 6. Accepted Risks and Limitations

The following limitations must be considered before using TrustVault for real sensitive information:

1. **HTTP deployment:** The current public URL does not provide verified HTTPS protection.
2. **Previously downloaded files:** Revoking access cannot erase copies a recipient has already downloaded.
3. **Audit-log integrity:** Application-level audit records are not assumed to be tamper-proof.
4. **File validation:** Extension and size checks do not replace comprehensive content inspection or malware scanning.
5. **Cloud configuration:** AWS IAM, S3 access controls, secret handling, and logging configuration require verification.
6. **Operational security:** Backups, disaster recovery, incident response, rate limiting, and production monitoring may require additional work.
7. **Security assurance:** Passing automated tests does not prove that every possible attack has been prevented.

These are known risks or areas requiring verification, not claims that every listed mitigation has already been fully implemented.

## 7. Future Improvements

- Configure and verify HTTPS using a suitable domain and certificate.
- Add stronger upload-content validation and malware scanning.
- Send security-critical audit records to a separately protected logging destination.
- Review IAM policies and S3 bucket settings using least privilege.
- Add rate limiting and monitoring for suspicious activity.
- Perform a route-by-route authorization review and additional adversarial tests.
- Document backup, recovery, and incident-response procedures.

## 8. Conclusion

TrustVault is designed around authentication, role-based authorization, document-level permissions, revocation, file integrity checks, and audit logging. Its security depends on correctly enforcing authorization on every relevant route, safely configuring the deployment, and verifying the behavior with automated and manual tests.

This threat model documents the intended protections and remaining risks. It is not a certification that the application is production-secure.
