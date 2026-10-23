# TrustVault — Secure Document Sharing

**Secure document sharing with role-based access control and an auditable trail.**

TrustVault is a Flask-based document-sharing application built for the Snovasys Fresher Hiring Challenge 2026. It aims to ensure that users can access only documents they are authorized to view and that document activity can be reviewed through audit records.

## Live Demo

[**TrustVault — Open Website**](http://3.91.27.213/)

**GitHub Repository:** [BattuMonishaNandini10/TrustVault](https://github.com/BattuMonishaNandini10/TrustVault)

> **Security warning:** The current demo uses HTTP, not HTTPS. Do not upload real, confidential, or personal documents to the demo.

## Features

- Authentication with administrator, owner and viewer roles
- Document upload and management
- Document-specific sharing permissions
- Granting and revoking access
- Server-side access-control checks
- SHA-256 document integrity verification
- Security and document activity logging
- Administrative audit view
- Automated security tests

Features should be considered verified only when confirmed in the current code and deployed environment.

## Technology Stack

- Python
- Flask
- SQLite
- AWS EC2
- Amazon S3 integration
- Amazon CloudWatch logging integration

## Role Model

| Role | Intended access |
|---|---|
| Administrator | Administrative functions and authorized audit review |
| Owner | Manage owned documents and grant or revoke access |
| Viewer | Access only documents shared with their account, within the granted permission |

Document permissions must be checked by the server on every protected request. Hiding a button is not sufficient authorization.

## Security Design

TrustVault is designed around three key principles:

1. **Authorization on every request:** A user must not access a document merely by guessing its URL or ID.
2. **Revocation:** Removing a permission must block subsequent server-mediated access.
3. **Auditing:** Important document actions and denied access attempts should be recorded so activity can be investigated.

SHA-256 can help detect file-content changes when compared with a trusted expected hash. It does not, by itself, make audit records tamper-proof.

## Testing

Run the automated tests from the project directory:

```bash
python -m pytest -q
```

A previous local test run reported 195 passing tests. Run the suite again on the final commit before submission; local test results do not prove that every deployed route is secure.

## Documentation

- `THREATS.md` — attack scenarios, mitigations and accepted risks
- `PROMPTS.md` — dated AI-use entries, mistakes and corrective work
- `API.md` — endpoint authorization documentation
- `SETUP.md` — setup and deployment instructions
- `TESTING.md` — security test plan and verification evidence
- `WRITEUP.md` — design decisions, AI use and unfinished work
- `DEMO_SCRIPT.md` — five-minute demo plan

## Known Limitations and Unfinished Work

- HTTPS has not yet been configured and verified for the current public demo.
- Audit tamper resistance must not be assumed unless independently protected and tested.
- AWS S3 storage and CloudWatch event delivery must be verified end to end on the deployed version.
- Additional adversarial testing is needed to check direct routes, permission revocation and unauthorized document access.
- The project is a hiring-challenge prototype, not a claim of production readiness.

## Demo Credentials

Add verified, challenge-only credentials for one administrator, one owner and one viewer before submission. Do not publish personal, reused or production passwords.

| Role | Username | Password |
|---|---|---|
| Administrator | Replace with verified demo username | Set a challenge-only password |
| Owner | Replace with verified demo username | Set a challenge-only password |
| Viewer | Replace with verified demo username | Set a challenge-only password |

Replace these placeholders only after confirming the accounts work on the deployed site.

## Demo Video

Add the link to your five-minute demo video here once it is recorded and available to the judges.

## Project Status

TrustVault has been developed and tested locally, and a previous test run reported 195 passing tests. Remaining deployment checks, documentation evidence and challenge submission must be completed and verified before the project is described as finished.
