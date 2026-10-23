# TrustVault — AI Prompt and Usage Log

This file documents how AI tools were used during TrustVault development, including useful suggestions, incorrect or incomplete output, and the corrective actions taken. Entries should reflect the actual development history.

**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail  
**Repository:** https://github.com/BattuMonishaNandini10/TrustVault

## Entry 1 — 18 October 2026: Understanding the challenge

**Prompt / task:** Explain the TrustVault problem statement and turn the requirements into a beginner-friendly implementation plan.

**AI output:** A breakdown of the document-sharing application, security requirements, and development steps.

**Issue identified:** A general implementation plan does not prove that every challenge requirement has been implemented or tested.

**Corrective action:** Compared the plan with the challenge requirements and tracked features such as role-based access, document permissions, revocation, audit logging, automated security tests, deployment, and documentation.

**Commit link:** Add the verified commit link for the related implementation or planning changes, if applicable.

## Entry 2 — 19 October 2026: Flask application setup and debugging

**Prompt / task:** Help configure the Flask application, templates, database, and login functionality, and diagnose errors encountered during development.

**AI output:** Suggested code and debugging steps for Flask routes, templates, SQLite, and authentication.

**Issue identified:** Some fixes required additional debugging, including template and route errors. Suggested code could not be assumed correct without running it.

**Corrective action:** Ran the application locally, checked errors in the terminal, corrected the affected files, and tested the relevant routes.

**Commit link:** Add the verified commit link for the related changes, if applicable.

## Entry 3 — 20 October 2026: Document-sharing permissions

**Prompt / task:** Help implement document sharing between users and restrict document access according to permissions.

**AI output:** Suggested permission checks and document-sharing workflow changes.

**Issue identified:** A document appearing in a user's shared-document list does not, by itself, prove that direct download requests are authorized correctly.

**Corrective action:** Tested sharing and downloading with separate demo accounts and checked that subsequent document requests enforce the intended access rules. Additional tests should cover direct requests and revoked permissions.

**Commit link:** Add the verified commit link for the related permission changes, if applicable.

## Entry 4 — 21 October 2026: Role-based authorization and audit access

**Prompt / task:** Diagnose authorization problems affecting owner, viewer, and administrator routes, including the administrator audit page.

**AI output:** Suggested role restrictions and route-level authorization fixes.

**Issue identified:** Authorization behavior was inconsistent during testing, and a protected route needed additional correction. A role restriction on one page does not guarantee that all related routes are protected.

**Corrective action:** Corrected the reported audit-route restriction and tested role-specific access. Continue verifying each sensitive route with all three roles.

**Commit link:** Add the verified commit link for the audit and authorization fix, if applicable.

## Entry 5 — 22 October 2026: Automated security tests

**Prompt / task:** Help develop and run automated tests for TrustVault security behavior, including unauthorized access.

**AI output:** Suggested test cases and approaches for isolating the database and checking authorization behavior.

**Issue identified:** Tests can pass while still missing an attack path. A test that only checks a normal page response may not prove that direct document access is denied.

**Corrective action:** Used a separate test database and expanded security testing. Historical test results included 75 passing security tests and 195 passing tests in the full suite; rerun the tests on the final code before submission.

**Commit link:** Add the verified commit link for the test changes, if applicable.

## AI Use and Verification

AI was used as a development assistant for planning, debugging, code suggestions, and test development. Its suggestions were treated as proposals rather than proof of correctness.

The application was tested through local execution and automated tests. Security-sensitive behavior requires explicit verification because an apparently working interface does not guarantee server-side authorization.

Before submission:

- Replace any inaccurate entry with the exact prompt and event from the actual conversation history.
- Verify dates against the conversation and Git history.
- Replace each placeholder with a real commit link, or state that no specific commit was identified.
- Include at least two real examples involving authorization, access control, or audit logging.
- Document any additional AI mistakes and the specific corrections made.
- Do not claim that AI-generated code was correct unless it was checked and tested.
