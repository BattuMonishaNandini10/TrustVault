# TrustVault — Setup Guide

## 1. Prerequisites

Install the following software:

- Python 3.12 or a compatible supported Python version.
- Git.
- A terminal such as Windows Command Prompt or PowerShell.
- An AWS account only if you intend to configure or test the AWS integrations.

## 2. Clone the Repository

```bash
git clone https://github.com/BattuMonishaNandini10/TrustVault.git
cd TrustVault
```

## 3. Create a Virtual Environment

### Windows

```bat
py -3.12 -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

## 4. Install Dependencies

If the repository contains `requirements.txt`, run:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If `requirements.txt` is missing, create and maintain it from the project's actual imports and verified environment. Do not assume that this command will work until the file is committed.

## 5. Configure Environment Variables

Set a strong secret key for local development. Do not commit real secrets to Git.

### Windows Command Prompt

```bat
set TRUSTVAULT_SECRET_KEY=replace-with-a-long-random-secret
```

### Linux / macOS

```bash
export TRUSTVAULT_SECRET_KEY='replace-with-a-long-random-secret'
```

These commands set the variable for the current terminal session. Configure any other environment variables required by the actual application, including AWS settings if applicable.

Never put AWS access keys, passwords, or production secrets in this file or in the repository.

## 6. Database Initialization

TrustVault uses SQLite.

Inspect the repository for the database initialization script and follow the application's actual setup process. If the project includes `init_users.py`, `init_db.py`, or another initialization script, use the correct script for the current version.

For example, only if `init_users.py` is intended to initialize the current schema:

```bash
python init_users.py
```

Do not run multiple initialization scripts blindly against an existing database. Confirm their purpose first.

## 7. Start the Application

Use the startup method supported by the current `app.py`.

A typical Flask development command is:

```bash
python -m flask --app app run --debug
```

If the application starts successfully, open:

http://127.0.0.1:5000/

Debug mode is for local development only. Do not use Flask's development server or debug mode as a production deployment configuration.

## 8. Demo Accounts

Use the demo accounts and passwords documented in `README.md`, if they are present and verified.

If the project has a seed script, inspect it before running it. Do not publish real user credentials or reuse demo passwords in production.

## 9. Run Automated Tests

Activate the virtual environment and run:

```bash
python -m pytest -q
```

To run the security test file specifically:

```bash
python -m pytest -q tests/test_security.py
```

Record the actual results from the final code. Passing tests on an earlier commit do not guarantee that later changes are correct.

## 10. AWS Deployment

TrustVault has been deployed to an AWS EC2 instance. The current public URL is:

http://3.91.27.213/

AWS-related configuration should be verified against the actual deployment. Document the real S3 bucket configuration, IAM permissions, CloudWatch logging setup, and production startup procedure only after confirming them.

The public deployment currently uses HTTP rather than verified HTTPS. Do not upload real sensitive documents or credentials through this URL.

## 11. Troubleshooting

- **`ModuleNotFoundError`:** Activate the virtual environment and install the required dependencies.
- **`TemplateNotFound`:** Confirm that the required HTML files exist in the `templates` directory.
- **Database errors:** Verify the configured database path and initialization procedure.
- **Login failures:** Confirm that the demo accounts were seeded correctly and that password hashing is configured as expected.
- **AWS errors:** Check the instance's IAM role, permissions, environment variables, service configuration, and logs. Avoid placing AWS secret keys in source code.
- **Port already in use:** Stop the previous development server or select another local port.

## 12. Security Notes

- Never commit `.env` files, credentials, production databases, or sensitive uploaded documents.
- Use a separate temporary database for tests.
- Verify authorization on direct document requests, not only on pages that list documents.
- Use HTTPS and least-privilege AWS permissions before handling sensitive production data.
- Review `THREATS.md` for the threat model and remaining limitations.

## 13. Related Documentation

- `README.md` — project overview and verified demo information.
- `THREATS.md` — security threats, mitigations, and accepted risks.
- `PROMPTS.md` — AI usage and corrections.
- `API.md` — application route documentation.
- `TESTING.md` — testing instructions and results.
- `WRITEUP.md` — project reflection.
- `DEMO_SCRIPT.md` — demonstration plan.

**Maintenance note:** Verify every command, filename, environment variable, and deployment instruction against the current repository before submitting this guide.
