# TrustVault Setup Guide

## 1. Prerequisites

Before setting up TrustVault, ensure that you have:

- Python 3.12 or another version supported by the project
- Git
- A copy of the TrustVault repository
- The project's dependency file, `requirements.txt`
- The database initialization instructions and scripts, if required

## 2. Obtain the Project

Open the TrustVault GitHub repository and download the source code using the GitHub website's **Code → Download ZIP** option.

Extract the downloaded ZIP file to a folder on your computer.

## 3. Install Dependencies

Open a terminal in the extracted project folder.

Create and activate a Python virtual environment, then install the dependencies listed in `requirements.txt`.

Use the dependency installation instructions appropriate for your operating system.

## 4. Configure Secrets

Configure the application secret using the environment variable expected by the application.

Do not commit `.env` files, passwords, AWS credentials, or production secrets to the repository.

Use disposable credentials for local testing and demo accounts.

## 5. Initialize the Database

Follow the database setup scripts and instructions included in the repository.

Use a fresh database for a new installation. Do not distribute a production database containing personal information or confidential documents.

## 6. Start the Application

Follow the development startup instructions appropriate to the project's actual Flask entry point and configuration.

Once the application starts, open the local URL displayed by the development server.

Do not expose the Flask development server directly to the public internet.

## 7. Run Automated Tests

Install the test dependencies and run the project's documented test suite.

Verify that the tests use an isolated test database and do not modify production data.

The security tests should cover authentication, role restrictions, document ownership, sharing permissions, and access revocation.

Record the actual test results before submitting the project.

## 8. Deployment

The deployed application is intended to run on AWS EC2.

The final deployment guide must document the verified server configuration, application service, reverse proxy if used, required environment variables, database setup, and live URL.

Never include private SSH keys, cloud credentials, or production secrets in the repository.

## 9. Troubleshooting

- **Dependency errors:** Confirm the Python version and install the listed project dependencies.
- **Database errors:** Review the database path, initialization steps, and file permissions.
- **Login errors:** Confirm that demo accounts were initialized and use the correct credentials.
- **Permission errors:** Check the intended role and document-level authorization rules.
- **Upload errors:** Check allowed file types, upload size limits, and private storage permissions.

## 10. Verification Status

This document is a setup guide draft. Exact commands, database initialization steps, environment variables, and deployment instructions must be checked against the actual project before the submission is considered reproducible.
