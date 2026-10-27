<#
.SYNOPSIS
    Performs a complete offboarding of a single Active Directory
    account, per SOP-IAM-001.

.DESCRIPTION
    Runs all five steps. Documents the account and its group
    memberships, verifies that record on disk, disables the
    account, stamps the authorising ticket, randomises the
    password, removes all group memberships, and moves the
    account to the Disabled Users OU.

    The script refuses to act, and changes nothing at all, if:
      the account does not exist
      the account is already disabled
      the account appears to be a service account
      the ticket is not in the form NMG-0000
      the group export cannot be verified on disk
    If the Disabled Users OU cannot be found, steps 1 to 4 are
    completed and the script stops before the move.

.PARAMETER Username
    The SamAccountName of the account to offboard. Mandatory.

.PARAMETER Ticket
    The authorising ticket, in the form NMG-0000. Mandatory.

.PARAMETER ReportPath
    Where the evidence CSV files are written.
    Default: C:\Reports\Offboarding

.PARAMETER LogPath
    Where the run transcript is written.
    Default: C:\nmg-identity-automation\Logs

.EXAMPLE
    .\Offboard-NMGUser.ps1 -Username "jdoe" -Ticket "NMG-0214" -WhatIf
    Runs every check and reports what it would do, changing
    nothing. Do this first, every time.

.EXAMPLE
    .\Offboard-NMGUser.ps1 -Username "jdoe" -Ticket "NMG-0214"
    Performs the complete offboarding.

.NOTES
    Author  : Chayse Tucker
    Created : 10/25/2026
    Implements all five steps of SOP-IAM-001.
    Renamed from Disable-NMGUser.ps1 once it performed all five.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$Username,

    [Parameter(Mandatory)]
    [string]$Ticket,

    [string]$ReportPath = "C:\Reports\Offboarding",
    [string]$LogPath    = "C:\nmg-identity-automation\Logs"
)

#--- SETUP --------------------------------------------------

Import-Module ActiveDirectory

$stamp = Get-Date -Format "yyyy-MM-dd_HHmm"

foreach ($p in @($ReportPath, $LogPath)) {
    if (-not (Test-Path $p)) {
        New-Item -Path $p -ItemType Directory -Force | Out-Null
    }
}

# Everything printed from here on ends up in a dated file.
# Never print a credential after this line.
Start-Transcript -Path "$LogPath\Offboard-NMGUser_$stamp.log" | Out-Null

Write-Host ""
Write-Host "  OFFBOARD-NMGUSER" -ForegroundColor Cyan
Write-Host "  Target : $Username"
Write-Host "  Ticket : $Ticket"
Write-Host "  Run by : $env:USERNAME"
Write-Host ""


#--- GATE 1: THE FOUR CHECKS --------------------------------
# Every one of these stops the script. A warning that scrolls
# past at 4:50 on a Friday is a decoration, not a guardrail.

# CHECK 1: does the account exist at all?
$user = Get-ADUser -Identity $Username -Properties * -ErrorAction SilentlyContinue

if (-not $user) {
    Write-Host "  STOP: no account named $Username" -ForegroundColor Red
    try { Stop-Transcript | Out-Null } catch { }
    return
}

# CHECK 2: has somebody already handled this one?
if ($user.Enabled -eq $false) {
    Write-Host "  STOP: $Username is already disabled." -ForegroundColor Yellow
    Write-Host "        Existing note: $($user.Description)" -ForegroundColor Gray
    Write-Host "        Re-running would overwrite that record." -ForegroundColor Gray
    try { Stop-Transcript | Out-Null } catch { }
    return
}

# CHECK 3: is this a person, or is it machinery?
if ($user.SamAccountName -like "svc_*" -or $user.Department -eq "Service Accounts") {
    Write-Host "  STOP: $Username looks like a service account." -ForegroundColor Red
    Write-Host "        Find its owner first. Different procedure." -ForegroundColor Gray
    try { Stop-Transcript | Out-Null } catch { }
    return
}

# CHECK 4: is the ticket a real shape?
if ($Ticket -notmatch "^NMG-\d{4}$") {
    Write-Host "  STOP: ticket should look like NMG-0000" -ForegroundColor Red
    try { Stop-Transcript | Out-Null } catch { }
    return
}

Write-Host "  All checks passed for $($user.Name)" -ForegroundColor Green


#--- STEP 1: DOCUMENT ---------------------------------------
# Runs on a WhatIf too. Reading changes nothing, and the record
# is worth having either way.

# @() makes .Count reliable even when there is only one group.
$groups = @(Get-ADPrincipalGroupMembership -Identity $Username)

# Domain Users is the primary group and cannot be removed.
$toRemove = @($groups | Where-Object { $_.Name -ne "Domain Users" })

$user |
  Select-Object Name, SamAccountName, Department, Title,
                LastLogonDate, Enabled, DistinguishedName |
  Export-Csv "$ReportPath\$($Username)_account_$stamp.csv" `
    -NoTypeInformation -Encoding UTF8

$groups |
  Select-Object Name, GroupCategory, DistinguishedName |
  Export-Csv "$ReportPath\$($Username)_groups_$stamp.csv" `
    -NoTypeInformation -Encoding UTF8

Write-Host "  Captured $($groups.Count) memberships" -ForegroundColor Green


#--- GATE 2: VERIFY THE RECORD ON DISK ----------------------
# $groups tells you the query worked. The file tells you the
# record actually exists.
#
# Export-Csv does not write on a dry run, so this only checks
# when the run is real. Otherwise every dry run would refuse.

if (-not $WhatIfPreference) {

    $groupFile = "$ReportPath\$($Username)_groups_$stamp.csv"

    if (-not (Test-Path $groupFile)) {
        Write-Host "  STOP: no export file was written." -ForegroundColor Red
        try { Stop-Transcript | Out-Null } catch { }
        return
    }

    $written = @(Import-Csv $groupFile)

    if ($written.Count -eq 0) {
        Write-Host "  STOP: export file is empty." -ForegroundColor Red
        Write-Host "        Refusing to remove unrecorded access." -ForegroundColor Gray
        try { Stop-Transcript | Out-Null } catch { }
        return
    }

    Write-Host "  Verified $($written.Count) memberships on disk" -ForegroundColor Green
}


#--- STEP 2: DISABLE AND STAMP ------------------------------
# ShouldProcess is what makes -WhatIf work. Everything inside
# these blocks is skipped on a WhatIf run.

if ($PSCmdlet.ShouldProcess($Username, "Disable account and stamp $Ticket")) {

    Disable-ADAccount -Identity $Username

    Set-ADUser -Identity $Username `
      -Description "Offboarded $(Get-Date -Format yyyy-MM-dd) | Ticket $Ticket"

    Write-Host "  Disabled and stamped." -ForegroundColor Green
}


#--- STEP 3: RANDOMISE THE PASSWORD -------------------------
# Never printed, never stored. Nobody needs to know it.
# Uses a cryptographic generator rather than Get-Random.

if ($PSCmdlet.ShouldProcess($Username, "Randomise password")) {

    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)

    # The suffix guarantees upper, lower, digit and symbol.
    $secure = ConvertTo-SecureString ([Convert]::ToBase64String($bytes) + "aA1!") `
                -AsPlainText -Force

    Set-ADAccountPassword -Identity $Username -Reset -NewPassword $secure
    Remove-Variable bytes, secure

    Write-Host "  Password randomised" -ForegroundColor Green
}


#--- STEP 4: REMOVE GROUP MEMBERSHIPS -----------------------
# The only step that cannot be reversed. Gate 2 above is the
# reason it is safe to reach this line.

if ($PSCmdlet.ShouldProcess($Username, "Remove $($toRemove.Count) memberships")) {

    $removed = @()
    $failed  = @()

    foreach ($g in $toRemove) {
        try {
            Remove-ADGroupMember -Identity $g -Members $Username `
                -Confirm:$false -ErrorAction Stop
            $removed += $g.Name
            Write-Host "  Removed: $($g.Name)" -ForegroundColor Yellow
        }
        catch {
            $failed += "$($g.Name)  ($($_.Exception.Message))"
        }
    }

    Write-Host ""
    Write-Host "  Removed : $($removed.Count)" -ForegroundColor Green

    if ($failed.Count -gt 0) {
        Write-Host "  FAILED  : $($failed.Count)" -ForegroundColor Red
        $failed | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    }
}


#--- GATE 3: CHECK THE DESTINATION --------------------------
# Built from Get-ADDomain at runtime, so nothing is hardcoded
# and the script works in any domain.

$root   = (Get-ADDomain).DistinguishedName
$target = "OU=Disabled Users,$root"

# Check the exact path we are about to aim at, not just any
# OU with the right name somewhere in the domain.
if (-not (Get-ADOrganizationalUnit -Identity $target -ErrorAction SilentlyContinue)) {
    Write-Host "  STOP: Disabled Users OU not found." -ForegroundColor Red
    Write-Host "        Steps 1 to 4 are done. Move by hand." -ForegroundColor Gray
    try { Stop-Transcript | Out-Null } catch { }
    return
}


#--- STEP 5: MOVE TO DISABLED USERS -------------------------
# Goes last, because moving an object changes its address and
# every earlier step refers to the old one.

# Look up where the account is RIGHT NOW. Not earlier.
$dn = (Get-ADUser -Identity $Username).DistinguishedName

if ($PSCmdlet.ShouldProcess($Username, "Move to Disabled Users")) {
    try {
        Move-ADObject -Identity $dn -TargetPath $target -ErrorAction Stop
        Write-Host "  Moved to quarantine." -ForegroundColor Green
    }
    catch {
        Write-Host "  MOVE FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "        Steps 1 to 4 are done. Move by hand." -ForegroundColor Gray
    }
}


#--- SUMMARY ------------------------------------------------
# Report where the account ended up. Somebody reading the log
# in November should not have to go and look.

$final = Get-ADUser -Identity $Username -Properties MemberOf

Write-Host ""
Write-Host "  Account  : $($user.Name) ($Username)"
Write-Host "  Ticket   : $Ticket"
Write-Host "  Enabled  : $($final.Enabled)"
Write-Host "  Groups   : $($final.MemberOf.Count)"
Write-Host "  Location : $($final.DistinguishedName)"
Write-Host "  Evidence : $ReportPath"
Write-Host ""

try { Stop-Transcript | Out-Null } catch { }