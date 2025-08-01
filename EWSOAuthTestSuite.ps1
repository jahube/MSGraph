# EWSOAuthTestSuite.ps1
# Comprehensive Test Suite for EWS OAuth in PowerShell (Office 365 Cloud)
# Date: August 01, 2025
# Description: This script tests delegated OAuth flow for EWS Managed API in PowerShell.
# It includes fallback error handling for common issues like Conditional Access (CA) policies,
# missing permissions (e.g., to mailbox or EWS scopes), and legacy auth blocks.
# Enhancements: Added retry for token acquisition, verbose output flag, JWT decoding for token validation,
# improved Exchange Online connection handling, and additional tests for folder access, reading emails,
# and calendar entries with graceful fallback for English/German folder names (Inbox/Posteingang, Calendar/Kalender).
# Requirements:
# - MSAL.PS module (Install-Module MSAL.PS -Force)
# - ExchangeOnlineManagement module (Install-Module ExchangeOnlineManagement -Force)
# - EWS Managed API DLL (v2.2) in the same directory as this script (Microsoft.Exchange.WebServices.dll)
# - Azure AD App registered as public client with delegated permission: EWS.AccessAsUser.All (admin consented)
# - Service user with MFA exemption for interactive login
# - Service user must have FullAccess on target mailbox (via Add-MailboxPermission)
# Usage: .\EWSOAuthTestSuite.ps1 -ClientId "your-app-id" -TenantId "your-tenant-id" -ServiceUser "service@domain.com" -TargetMailbox "target@domain.com" [-VerboseOutput]

param (
    [Parameter(Mandatory=$true)]
    [string]$ClientId,          # Azure AD App ID (public client)

    [Parameter(Mandatory=$true)]
    [string]$TenantId,          # Tenant ID

    [Parameter(Mandatory=$true)]
    [string]$ServiceUser,       # Service user email (for delegated auth)

    [Parameter(Mandatory=$true)]
    [string]$TargetMailbox,     # Target mailbox to access (shared or user)

    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput,     # Enable verbose logging

    [Parameter(Mandatory=$false)]
    [string]$EwsDllPath = ".\Microsoft.Exchange.WebServices.dll"  # Path to EWS DLL
)

# Global variables for test results
$TestResults = @{}
$OverallPass = $true

# Helper Function: Report Test Result
function Report-TestResult {
    param (
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = "",
        [string]$ErrorDetails = ""
    )
    $TestResults[$TestName] = @{
        Passed = $Passed
        Message = $Message
        ErrorDetails = $ErrorDetails
    }
    if (-not $Passed) { $script:OverallPass = $false }
    Write-Host "[$TestName] - Passed: $Passed - $Message" -ForegroundColor $(if ($Passed) { "Green" } else { "Red" })
    if ($ErrorDetails) { Write-Host "Details: $ErrorDetails" -ForegroundColor Yellow }
    if ($VerboseOutput) { Write-Verbose "Full details for $TestName`: Passed=$Passed, Message=$Message, Error=$ErrorDetails" }
}

# Helper Function: Decode JWT (for token validation)
function Decode-JWT {
    param ([string]$token)
    try {
        $parts = $token -split '\.'
        if ($parts.Length -lt 2) { return $null }
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        $payload += '=' * (4 - ($payload.Length % 4))
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
        return ($decoded | ConvertFrom-Json)
    } catch {
        return $null
    }
}

# Test 1: Module and DLL Availability
function Test-Prerequisites {
    $passed = $true
    $message = "All prerequisites met."
    $errorDetails = ""

    # Check MSAL.PS
    if (-not (Get-Module -ListAvailable -Name MSAL.PS)) {
        $passed = $false
        $errorDetails += "MSAL.PS module missing. Run: Install-Module MSAL.PS -Force`n"
    }

    # Check ExchangeOnlineManagement
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        $passed = $false
        $errorDetails += "ExchangeOnlineManagement module missing. Run: Install-Module ExchangeOnlineManagement -Force`n"
    }

    # Check EWS DLL
    if (-not (Test-Path $EwsDllPath)) {
        $passed = $false
        $errorDetails += "EWS DLL not found at $EwsDllPath. Download from Microsoft.`n"
    } else {
        try {
            Add-Type -Path $EwsDllPath -ErrorAction Stop
        } catch {
            $passed = $false
            $errorDetails += "Failed to load EWS DLL: $($_.Exception.Message)`n"
        }
    }

    Report-TestResult -TestName "Prerequisites" -Passed $passed -Message $message -ErrorDetails $errorDetails
    return $passed
}

# Test 2: Token Acquisition (Delegated OAuth) with Retry
function Test-TokenAcquisition {
    $passed = $true
    $message = "Token acquired successfully."
    $errorDetails = ""
    $token = $null
    $retryCount = 0
    $maxRetries = 2

    while (-not $token -and $retryCount -lt $maxRetries) {
        try {
            # Scopes for delegated EWS
            $scopes = @("https://outlook.office365.com/EWS.AccessAsUser.All")

            # Attempt silent acquisition first
            $token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $scopes -Silent -ErrorAction Stop

            if (-not $token) {
                Write-Host "No cached token; acquiring interactively (login as $ServiceUser)..."
                $token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $scopes -Interactive -UseEmbeddedWebView -ErrorAction Stop
            }

            # Force refresh if near expiry
            if ($token.ExpiresOn - (Get-Date) -lt (New-TimeSpan -Minutes 5)) {
                Write-Host "Token expiring soon; refreshing silently..."
                $token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $scopes -ForceRefresh -ErrorAction Stop
            }

            # Validate token expiry and log
            if ($VerboseOutput) { Write-Verbose "Token ExpiresOn: $($token.ExpiresOn)" }

            # Decode and validate JWT claims
            $jwt = Decode-JWT $token.AccessToken
            if ($jwt) {
                if ($VerboseOutput) { $jwt | Select-Object aud, scp, upn | Format-List | Out-String | Write-Verbose }
                if ($jwt.aud -ne "https://outlook.office365.com" -or $jwt.scp -notmatch "EWS.AccessAsUser.All") {
                    throw "Invalid token claims: aud or scp mismatch."
                }
            } else {
                throw "Failed to decode JWT."
            }
        } catch {
            $retryCount++
            $passed = $false
            $message = "Token acquisition failed after $retryCount retries."
            $errorDetails = $_.Exception.Message

            # Fallback Handling
            if ($errorDetails -match "AADSTS70043" -or $errorDetails -match "Conditional Access") {
                $errorDetails += "`nFallback: Conditional Access policy may be blocking. Check Azure AD > Conditional Access for policies requiring MFA or device compliance. Exempt $ServiceUser if needed."
            } elseif ($errorDetails -match "AADSTS50076" -or $errorDetails -match "legacy") {
                $errorDetails += "`nFallback: Legacy auth block detected in CA. Ensure app uses modern auth (OAuth) and no basic auth fallback."
            } elseif ($errorDetails -match "permission" -or $errorDetails -match "scope") {
                $errorDetails += "`nFallback: Missing EWS.AccessAsUser.All permission. Check Azure AD app registration and grant admin consent."
            }
            if ($retryCount -lt $maxRetries) {
                Write-Host "Retrying token acquisition ($retryCount/$maxRetries)..."
                Start-Sleep -Seconds 5
            }
        }
    }

    Report-TestResult -TestName "TokenAcquisition" -Passed $passed -Message $message -ErrorDetails $errorDetails
    return $token
}

# Test 3: EWS Service Connection
function Test-EWSConnection {
    param ([string]$AccessToken)

    $passed = $true
    $message = "EWS service connected successfully."
    $errorDetails = ""
    $service = $null

    try {
        if (-not $AccessToken) { throw "No access token provided." }

        $service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2016)
        $service.Url = New-Object Uri("https://outlook.office365.com/EWS/Exchange.asmx")
        $service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($AccessToken)

        # Test basic autodiscover or ping (simple GetFolder on root to verify connection)
        $rootFolder = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot, (New-Object Microsoft.Exchange.WebServices.Data.Mailbox($ServiceUser)))
        $null = $service.BindToFolder($rootFolder, [Microsoft.Exchange.WebServices.Data.PropertySet]::FirstClassProperties)
    } catch {
        $passed = $false
        $message = "EWS connection failed."
        $errorDetails = $_.Exception.Message

        # Fallback Handling
        if ($errorDetails -match "401" -or $errorDetails -match "Unauthorized") {
            $errorDetails += "`nFallback: Invalid token or scope. Verify token audience is 'https://outlook.office365.com' and includes EWS.AccessAsUser.All."
        } elseif ($errorDetails -match "403" -or $errorDetails -match "Forbidden") {
            $errorDetails += "`nFallback: Conditional Access or permission issue. Check CA policies or run Test-ApplicationAccessPolicy -Identity $ServiceUser -AppId $ClientId."
        } elseif ($errorDetails -match "Graph") {
            $errorDetails += "`nFallback: Scope mismatch? EWS uses Exchange scopes, not Graph. Ensure scope is 'https://outlook.office365.com/EWS.AccessAsUser.All'."
        }
    }

    Report-TestResult -TestName "EWSConnection" -Passed $passed -Message $message -ErrorDetails $errorDetails
    return $service
}

# Test 4: Mailbox Permissions Check (with Auto-Connect to Exchange Online)
function Test-MailboxPermissions {
    $passed = $true
    $message = "Mailbox permissions verified."
    $errorDetails = ""

    try {
        # Auto-connect to Exchange Online if not already connected
        if (-not (Get-Command Get-MailboxPermission -ErrorAction SilentlyContinue)) {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop
            try {
                Connect-ExchangeOnline -UserPrincipalName $ServiceUser -ErrorAction Stop
            } catch {
                throw "Failed to connect to Exchange Online: $($_.Exception.Message). Check MFA/CA for $ServiceUser."
            }
        }

        $perms = Get-MailboxPermission -Identity $TargetMailbox | Where-Object { $_.User -like "*$ServiceUser*" -and $_.AccessRights -contains "FullAccess" }
        if (-not $perms) {
            throw "No FullAccess permission for $ServiceUser on $TargetMailbox."
        }

        # Check EWSEnabled
        $cas = Get-CASMailbox $TargetMailbox
        if (-not $cas.EwsEnabled) {
            throw "EWSEnabled is false on $TargetMailbox."
        }
    } catch {
        $passed = $false
        $message = "Mailbox permissions check failed."
        $errorDetails = $_.Exception.Message

        # Fallback Handling
        $errorDetails += "`nFallback: Grant permissions with Add-MailboxPermission -Identity $TargetMailbox -User $ServiceUser -AccessRights FullAccess. Also, set Set-CASMailbox $TargetMailbox -EWSEnabled $true."
        if ($errorDetails -match "Conditional Access" -or $errorDetails -match "MFA") {
            $errorDetails += "`nAdditional: Connection to EXO failed due to CA/MFA. Exempt $ServiceUser or use app-only auth for EXO."
        }
    }

    Report-TestResult -TestName "MailboxPermissions" -Passed $passed -Message $message -ErrorDetails $errorDetails
}

# Test 5: Target Mailbox Access (Folder Binding)
function Test-TargetMailboxAccess {
    param ([object]$Service)

    $passed = $true
    $message = "Target mailbox folders accessed successfully."
    $errorDetails = ""

    try {
        if (-not $Service) { throw "No EWS service provided." }

        # Add X-AnchorMailbox for delegated access to shared mailbox
        if ($Service.HttpHeaders.ContainsKey("X-AnchorMailbox")) {
            $Service.HttpHeaders["X-AnchorMailbox"] = $TargetMailbox
        } else {
            $Service.HttpHeaders.Add("X-AnchorMailbox", $TargetMailbox)
        }

        # Bind to MsgFolderRoot
        $mailbox = New-Object Microsoft.Exchange.WebServices.Data.Mailbox($TargetMailbox)
        $rootId = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot, $mailbox)
        $root = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($Service, $rootId)

        # List top-level folders for validation
        $view = New-Object Microsoft.Exchange.WebServices.Data.FolderView(10)
        $folders = $Service.FindFolders($rootId, $view)
        if ($VerboseOutput) {
            Write-Verbose "Top folders: $($folders.Folders | Select-Object -ExpandProperty DisplayName -First 5)"
        }
    } catch {
        $passed = $false
        $message = "Target mailbox folder access failed."
        $errorDetails = $_.Exception.Message

        # Fallback Handling
        if ($errorDetails -match "403" -or $errorDetails -match "Forbidden") {
            $errorDetails += "`nFallback: Possible CA policy or missing mailbox permission. Verify FullAccess for $ServiceUser on $TargetMailbox. If needed, add ApplicationAccessPolicy."
        } elseif ($errorDetails -match "401") {
            $errorDetails += "`nFallback: Token issue; re-acquire token or check scopes."
        } elseif ($errorDetails -match "legacy") {
            $errorDetails += "`nFallback: Ensure no legacy auth in code; CA may block it."
        }
    }

    Report-TestResult -TestName "TargetMailboxAccess" -Passed $passed -Message $message -ErrorDetails $errorDetails
}

# Test 6: Read Test Email from Inbox (with English/German Fallback)
function Test-ReadEmail {
    param ([object]$Service)

    $passed = $true
    $message = "Test email read from Inbox successfully."
    $errorDetails = ""

    try {
        if (-not $Service) { throw "No EWS service provided." }

        $mailbox = New-Object Microsoft.Exchange.WebServices.Data.Mailbox($TargetMailbox)

        # Try English "Inbox" first
        try {
            $inboxId = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox, $mailbox)
            $inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($Service, $inboxId)
        } catch {
            # Fallback to German "Posteingang"
            $errorDetails += "English 'Inbox' failed; trying German 'Posteingang'...`n"
            $inboxId = $null
            $view = New-Object Microsoft.Exchange.WebServices.Data.FolderView(1)
            $sf = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName, "Posteingang")
            $rootId = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot, $mailbox)
            $results = $Service.FindFolders($rootId, $sf, $view)
            if ($results.TotalCount -gt 0) {
                $inboxId = $results.Folders[0].Id
                $inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($Service, $inboxId)
            } else {
                throw "Inbox/Posteingang not found."
            }
        }

        # Read top email
        $itemView = New-Object Microsoft.Exchange.WebServices.Data.ItemView(1)
        $items = $Service.FindItems($inboxId, $itemView)
        if ($items.TotalCount -gt 0) {
            $email = [Microsoft.Exchange.WebServices.Data.EmailMessage]::Bind($Service, $items.Items[0].Id)
            if ($VerboseOutput) { Write-Verbose "Test Email Subject: $($email.Subject)" }
        } else {
            $message += " (No emails in Inbox; test passed but empty)."
        }
    } catch {
        $passed = $false
        $message = "Reading test email failed."
        $errorDetails += $_.Exception.Message
    }

    Report-TestResult -TestName "ReadEmail" -Passed $passed -Message $message -ErrorDetails $errorDetails
}

# Test 7: Read Calendar Entries (with English/German Fallback)
function Test-ReadCalendar {
    param ([object]$Service)

    $passed = $true
    $message = "Calendar entries read successfully."
    $errorDetails = ""

    try {
        if (-not $Service) { throw "No EWS service provided." }

        $mailbox = New-Object Microsoft.Exchange.WebServices.Data.Mailbox($TargetMailbox)

        # Try English "Calendar" first
        try {
            $calendarId = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Calendar, $mailbox)
            $calendar = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($Service, $calendarId)
        } catch {
            # Fallback to German "Kalender"
            $errorDetails += "English 'Calendar' failed; trying German 'Kalender'...`n"
            $calendarId = $null
            $view = New-Object Microsoft.Exchange.WebServices.Data.FolderView(1)
            $sf = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName, "Kalender")
            $rootId = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot, $mailbox)
            $results = $Service.FindFolders($rootId, $sf, $view)
            if ($results.TotalCount -gt 0) {
                $calendarId = $results.Folders[0].Id
                $calendar = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($Service, $calendarId)
            } else {
                throw "Calendar/Kalender not found."
            }
        }

        # Read top calendar entry (appointment)
        $itemView = New-Object Microsoft.Exchange.WebServices.Data.ItemView(1)
        $items = $Service.FindItems($calendarId, $itemView)
        if ($items.TotalCount -gt 0) {
            $appt = [Microsoft.Exchange.WebServices.Data.Appointment]::Bind($Service, $items.Items[0].Id)
            if ($VerboseOutput) { Write-Verbose "Test Calendar Entry Subject: $($appt.Subject)" }
        } else {
            $message += " (No entries in Calendar; test passed but empty)."
        }
    } catch {
        $passed = $false
        $message = "Reading calendar entries failed."
        $errorDetails += $_.Exception.Message
    }

    Report-TestResult -TestName "ReadCalendar" -Passed $passed -Message $message -ErrorDetails $errorDetails
}

# Run All Tests Sequentially
if (Test-Prerequisites) {
    $token = Test-TokenAcquisition
    if ($token) {
        $service = Test-EWSConnection -AccessToken $token.AccessToken
        if ($service) {
            Test-MailboxPermissions
            Test-TargetMailboxAccess -Service $service
            Test-ReadEmail -Service $service
            Test-ReadCalendar -Service $service
        }
    }
}

# Summary Report
Write-Host "`n--- Test Suite Summary ---"
foreach ($test in $TestResults.Keys) {
    $result = $TestResults[$test]
    Write-Host "$test : Passed=$($result.Passed) - $($result.Message)"
}
Write-Host "Overall Result: $(if ($OverallPass) { "PASS" } else { "FAIL" })" -ForegroundColor $(if ($OverallPass) { "Green" } else { "Red" })
