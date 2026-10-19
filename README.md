# NMG Identity Automation

PowerShell tools for finding and managing stale accounts in Active Directory.
Built during the TotalThreat 30-Day Challenge in a simulated healthcare
environment. Northstar Medical Group is a fictional organization.

## The Problem

At Northstar, offboarding depended on one person emailing IT whenever
someone left. When she retired, those emails stopped, and for 102 days
nobody noticed that departed employees still had working accounts.

A manual review eventually compared Active Directory against payroll and
found 23 stale accounts. It took 11 hours, and it still had a blind spot:
it could only find what had been recorded. Contractors who were never on
payroll, departures nobody filed, and service accounts that were never
people at all couldn't show up in that comparison.

## The Approach

Instead of trusting the paperwork, I asked the domain controller directly.
Every account has a LastLogonDate showing when it last authenticated, and
that value doesn't depend on HR records or names matching between systems.

Running this against the directory found 14 accounts that were dormant
for 90+ days and still enabled, none of which the manual review had caught.

The goal is to find first and fix later. These tools report on accounts;
they don't change them. Disabling accounts without a documented process is
how a small problem turns into an outage.

## Tools

### Find-StaleAccounts.ps1

Finds enabled accounts that haven't logged in within a set number of days,
including accounts that have never logged in at all. Saves a timestamped
CSV report and a summary file showing the exact query used, so anyone can
reproduce the results.

    .\Find-StaleAccounts.ps1
    .\Find-StaleAccounts.ps1 -Days 30
    .\Find-StaleAccounts.ps1 -Days 180 -IncludeDisabled

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Days` | int | 90 | Days without a login before an account counts as stale |
| `-ReportPath` | string | C:\Reports | Folder where reports are saved |
| `-IncludeDisabled` | switch | off | Also include disabled accounts |

Run `Get-Help .\Find-StaleAccounts.ps1 -Full` for full documentation.

## Repository Structure

    Scripts/        PowerShell tools
    Documentation/  Runbooks and process documentation
    Evidence/       Sample output and screenshots
    Logs/           Execution logs

## Requirements

- Windows Server with Active Directory Domain Services
- ActiveDirectory PowerShell module

## About

Built during the TotalThreat 30-Day Challenge in a simulated
healthcare environment. Northstar Medical Group is fictional.

Author: Chayse Tucker
