# Loading mock Entra data.
# In a production enviroment data would be obtained via
# Microsoft Graph connection using read-only permissions such as
# User.Read.All, Directory.Read.All, Policy.Read.All, and AuditLog.Read.All

$Users = Get-Content ".\MockData\users.json" | ConvertFrom-Json
$ConditionalAccess = Get-Content ".\MockData\conditionalAccess.json" | ConvertFrom-Json

$Results = @()


# First Check: Global Administrator Count
# --------------------------------------------------

$GlobalAdmins = $Users | Where-Object {
    $_.IsGlobalAdmin -eq $true
}

if ($GlobalAdmins.Count -gt 5) {

    $Results += [PSCustomObject]@{
        Category = "Identity"
        Check    = "Global Administrator Count"
        Status   = "FAIL"
        Severity = "High"
        Finding  = "$($GlobalAdmins.Count) Global Administrators detected"
    }

}
else {

    $Results += [PSCustomObject]@{
        Category = "Identity"
        Check    = "Global Administrator Count"
        Status   = "PASS"
        Severity = "Low"
        Finding  = "$($GlobalAdmins.Count) Global Administrators detected"
    }
}


# Second Check:  Privileged Accounts Without MFA
# --------------------------------------------------

$AdminsWithoutMFA = $GlobalAdmins | Where-Object {
    $_.MFARegistered -eq $false
}

if ($AdminsWithoutMFA.Count -gt 0) {

    $Results += [PSCustomObject]@{
        Category = "Identity"
        Check    = "Privileged Account MFA"
        Status   = "FAIL"
        Severity = "Critical"
        Finding  = "$($AdminsWithoutMFA.Count) Global Administrator(s) without MFA"
    }

}
else {

    $Results += [PSCustomObject]@{
        Category = "Identity"
        Check    = "Privileged Account MFA"
        Status   = "PASS"
        Severity = "Low"
        Finding  = "All Global Administrators have MFA"
    }
}


# Third check: Inactive Guest Accounts
# --------------------------------------------------

$InactiveGuests = $Users | Where-Object {
    $_.UserType -eq "Guest" -and
    $_.LastSignInDays -gt 90
}

if ($InactiveGuests.Count -gt 0) {

    $Results += [PSCustomObject]@{
        Category = "Identity"
        Check    = "Inactive Guest Accounts"
        Status   = "WARN"
        Severity = "Medium"
        Finding  = "$($InactiveGuests.Count) guest account(s) inactive for more than 90 days"
    }

}
else {

    $Results += [PSCustomObject]@{
        Category = "Identity"
        Check    = "Inactive Guest Accounts"
        Status   = "PASS"
        Severity = "Low"
        Finding  = "No inactive guest accounts detected"
    }
}


# Fourth Check: Conditional Access MFA
# --------------------------------------------------

$MFAPolicy = $ConditionalAccess | Where-Object {
    $_.RequiresMFA -eq $true -and
    $_.State -eq "enabled"
}

if ($MFAPolicy) {

    $Results += [PSCustomObject]@{
        Category = "Conditional Access"
        Check    = "MFA Policy"
        Status   = "PASS"
        Severity = "Low"
        Finding  = "Enabled Conditional Access MFA policy detected"
    }

}
else {

    $Results += [PSCustomObject]@{
        Category = "Conditional Access"
        Check    = "MFA Policy"
        Status   = "FAIL"
        Severity = "Critical"
        Finding  = "No enabled Conditional Access MFA policy detected"
    }
}


# Final Security Score
# --------------------------------------------------

$Score = 100

foreach ($Result in $Results) {

    if ($Result.Status -eq "FAIL") {
        $Score -= 25
    }

    if ($Result.Status -eq "WARN") {
        $Score -= 10
    }
}

if ($Score -lt 0) {
    $Score = 0
}


# Results Output
# --------------------------------------------------

Write-Host ""
Write-Host "============================================="
Write-Host "       ENTRA ID SECURITY BASELINE"
Write-Host "============================================="
Write-Host ""

$Results | Format-Table Category,Check,Status,Severity,Finding -AutoSize

Write-Host ""
Write-Host "Security Score: $Score / 100"
