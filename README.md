# AWS IAM Compliance Auditor

## Overview
An automated cloud security tool designed to audit AWS Identity and Access Management (IAM) configurations against strict SOC 2 compliance standards. This script replaces manual security reviews by programmatically generating, downloading, and parsing AWS credential reports to flag access control vulnerabilities.

## Business Value
In enterprise cloud environments, misconfigured IAM roles are a primary vector for security breaches. This tool automates the enforcement of:
* **SOC 2 CC6.1 (Logical Access):** Verifies that all human users have Multi-Factor Authentication (MFA) enabled.
* **SOC 2 CC6.2 (Credential Management):** Identifies stale access keys and "ghost accounts" (users who have not logged in recently) to enforce the principle of least privilege.

## Tech Stack
* **Language:** Python 3
* **Cloud API:** AWS SDK (Boto3)
* **Data Processing:** Pandas
* **Security:** AWS CLI (for secure, local credential management without hardcoding keys)

## Prerequisites
1. Python 3.x installed.
2. AWS CLI configured locally with valid IAM credentials (`aws configure`).
3. Required Python libraries:
   ```bash
   pip install boto3 pandas