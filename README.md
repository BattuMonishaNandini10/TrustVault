Live Demo: [TrustVault]((https://3.91.27.213/))

# TrustVault

**Secure document sharing with role-based access control and an auditable trail.**

TrustVault is a web application designed to help users share documents securely. It aims to ensure that users can access only the documents they are authorized to view and that document activity can be reviewed through audit records.

## Project Goals

- Authenticate users before granting access to protected features.
- Separate permissions for owners, viewers, and administrators.
- Support document uploads and controlled sharing.
- Allow document owners to grant and revoke access.
- Record document-related events for auditing.
- Verify document integrity using SHA-256 hashes.
- Test authorization rules to prevent unauthorized document access.

## Technology Stack

- **Language:** Python
- **Web framework:** Flask
- **Database:** SQLite
- **Authentication:** Flask-Login and password hashing
- **File integrity:** SHA-256
- **Deployment:**AWS EC2, with the deployment configuration documented as verified
- **Testing:** Pytest

## Roles and Permissions

| Role | Intended permissions |
|---|---|
| Owner | Upload and manage owned documents and control sharing permissions |
| Viewer | Access documents explicitly shared with them |
| Admin | Access authorized administrative features and audit records |

Actual permissions are enforced by the application and must be verified using automated tests.

## Security Design

TrustVault is designed around the principle of least privilege.

- Authenticate users before allowing protected operations.
- Check document-level permissions on every relevant access request.
- Restrict access to private file storage.
- Revoke sharing permissions when access is no longer required.
- Record relevant actions and denied attempts in audit records.
- Verify file integrity where supported by the application.
- Test that one user cannot access another user's documents without permission.

See [THREATS.md](THREATS.md) for the threat model and security verification status.

## Local Setup

1. Install a compatible Python version.
2. Clone this repository.
3. Create and activate a virtual environment.
4. Install dependencies from `requirements.txt`.
5. Follow the database initialization instructions provided with the project.
6. Configure the required application secret using an environment variable.
7. Start the Flask application using the documented development instructions.

Detailed clean-clone instructions will be added after the repository's application files and setup scripts have been checked.

## Testing

Run the documented automated test suite after installing the project dependencies. The security tests should verify that unauthorized users cannot access protected documents and that access-control failures are detected.

Test commands and expected results will be documented after confirming the repository's actual test configuration.

## Deployment

The project is intended to run on AWS EC2. Deployment documentation will identify the services actually used, configuration requirements, and steps to launch the application.

**Live application:** To be added after the deployed application and its access controls have been verified.

## Demo Accounts

Disposable demo accounts for the owner, viewer, and admin roles will be documented after confirming that the live environment is seeded and working. Credentials must never be reused from personal accounts.

## Project Documentation

- [Threat Model](THREATS.md) — threats, mitigations, and verification status.
- [AI Prompt Log](PROMPTS.md) — dated AI-assisted development records.
- [API Documentation](API.md) — endpoints and their permission requirements.
- [Project Write-up](WRITEUP.md) — architecture, design decisions, AI usage, and known limitations.

These documents will be added as the submission is prepared.

## Known Limitations

The final submission will explicitly list any features, tests, or deployment controls that remain incomplete or unverified.

## Author

Created for the Snovasys Fresher Hiring Challenge 2026.
