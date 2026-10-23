# TrustVault AI Prompt Log

## Purpose

This document records how AI assistance was used while developing TrustVault. AI-generated suggestions were treated as drafts and required review, testing, and correction.

The entries below summarize development activities. Exact dates, prompts, outputs, fixes, and commit links must be checked against the actual conversation history and GitHub commits before final submission.

## Entry 1 — Project Planning and Architecture

**Date:** 2026-10-18

**Area:** Architecture and project planning

**Prompt summary:** Explain the TrustVault challenge in beginner-friendly language and create a development plan for a secure document-sharing application.

**AI output:** A phased plan covering authentication, roles, document sharing, audit records, testing, deployment, and documentation.

**Review and outcome:** The plan helped organize the work into manageable stages. Implementation details were checked against the challenge requirements.

**Evidence / commit:** Add the relevant GitHub commit link after checking the repository history.

## Entry 2 — Authentication and Session Handling

**Date:** 2026-10-19

**Area:** Authentication

**Prompt summary:** Help implement and test login, password hashing, and session handling in the Flask application.

**AI output:** Guidance for authentication routes, password verification, and session management.

**Issue to record:** Document any actual implementation or testing issue encountered during authentication.

**Fix and verification:** Record the precise change made and the test or manual check used to verify it.

**Evidence / commit:** Add the corresponding commit link.

## Entry 3 — Role-Based Access Control

**Date:** 2026-10-20

**Area:** Authorization

**Prompt summary:** Help distinguish owner, viewer, and admin permissions and protect role-restricted routes.

**AI output:** Guidance for server-side role checks and route authorization.

**Issue observed:** A role-restricted page returned an access-denied response during testing. The exact route, role, and cause should be recorded from the development history.

**Fix and verification:** Document the actual authorization change and confirm that allowed roles succeed while unauthorized roles are denied.

**Evidence / commit:** Add the relevant commit link.

## Entry 4 — Document Sharing and Access Control

**Date:** 2026-10-20

**Area:** Document-level authorization

**Prompt summary:** Help test document sharing, access grants, revocation, and downloads by authorized recipients.

**AI output:** Step-by-step testing guidance for owner and viewer workflows.

**Observed outcome:** The shared-document download workflow was reported to work during manual testing.

**Security review:** Verify that an unrelated user cannot download the same document by changing its identifier and that revoked access is denied.

**Evidence / commit:** Add the corresponding implementation and test commit links.

## Entry 5 — Audit Logging and Security Testing

**Date:** 2026-10-22

**Area:** Audit trail and automated tests

**Prompt summary:** Help review audit access restrictions and test whether authorization controls prevent unauthorized document access.

**AI output:** Guidance for role-restricted audit access and isolated security tests.

**Issue observed:** An audit-route role restriction required correction during development.

**Fix and verification:** Record the exact change and the automated test result. Confirm that the test fails if the relevant authorization check is removed.

**Evidence / commit:** Add the actual fix and test commit links.

## AI Use and Limitations

AI was used as a development assistant for planning, debugging, implementation guidance, and test design. Suggestions were not treated as proof of security.

Potential limitations included incorrect assumptions about existing routes, templates, database structure, or role permissions. The application needed repeated manual checks and code corrections.

Security-sensitive suggestions were reviewed against the actual implementation. Any remaining unverified controls must be disclosed in the final submission.

## Final Evidence Checklist

- [ ] Confirm every date against the actual conversation or commit history.
- [ ] Replace generalized prompt summaries with the actual prompts used.
- [ ] Record the specific AI output relevant to each entry.
- [ ] Describe the real issue encountered and the exact fix applied.
- [ ] Add links to actual GitHub commits.
- [ ] Include evidence from automated tests where available.
- [ ] Do not invent test results, commits, or fixes.
