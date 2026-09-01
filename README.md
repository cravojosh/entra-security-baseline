# Entra ID Security Baseline Scanner

PowerShell proof-of-concept security scanner designed to evaluate Microsoft Entra ID configurations against common security controls.

## Purpose

This project demonstrates how a security baseline scanner can:

- Collect identity and configuration data
- Evaluate security controls
- Identify security weaknesses
- Assign severity levels
- Produce standardized findings
- Calculate an overall security score

## Current Checks

| Category | Check |
|---|---|
| Identity | Global Administrator count |
| Identity | Privileged accounts without MFA |
| Identity | Inactive guest accounts |
| Conditional Access | MFA policy |

## Architecture

Mock Entra Data
        ->
PowerShell Scanner
        ->
Security Checks
        ->
PASS / WARN / FAIL
        ->
Security Score

## Data Sources

Due to lack of M365 Tenant for testing, this proof of concept uses simulated JSON data.

A production environment would likely use Microsoft Graph API queries to pull real world data.

A Production Environment could easily expand this simple baseline scanner to retrieve the following:

- Users
- Directory roles
- Conditional Access policies
- Sign-in activity
- Authentication methods
- Enterprise applications
- Device information

Additional security controls could also be added to the scanning engine as well

## Philosophy

The scanner is designed as a read-only assessment tool. It identifies
security issues but does not make configuration changes to the tenant.
