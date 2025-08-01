<#
.SYNOPSIS
    PowerShell module for EWS OAuth authentication and token management.
.DESCRIPTION
    Provides Get-AppToken, Get-DelegatedToken, and New-EwsService functions with automatic caching and refresh.
#>

# Sanity check for MSAL.PS version
$msalModule = Get-Module MSAL.PS -ListAvailable | Select-Object -First 1
if ($msalModule.Version -ne [Version]"4.36.1.2") {
    Write-Warning "MSAL.PS version must be 4.36.1.2 for compatibility; current is $($msalModule.Version). Version 4.37.0.0 has known issues with token acquisition in some scenarios."
    Write-Warning "To fix: Uninstall-Module MSAL.PS; Install-Module MSAL.PS -RequiredVersion 4.36.1.2 -Force"
}

# Token cache in memory
Set-Variable -Name TokenCache -Value @{} -Scope Script -Force

function Get-AppToken {
    <#
    .SYNOPSIS
        Acquire or retrieve cached application token (client credentials).
    .PARAMETER ClientId
        Azure AD application (client) ID.
    .PARAMETER TenantId
        Azure AD tenant ID.
    .PARAMETER ClientSecret
        Client secret as SecureString.
    .PARAMETER ForceRefresh
        Switch to ignore cache and force new token acquisition.
    .OUTPUTS
        A PSObject with properties: AccessToken, ExpiresOn, Timestamp
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ClientId,
        [Parameter(Mandatory)] [string] $TenantId,
        [Parameter(Mandatory)] [SecureString] $ClientSecret,
        [switch] $ForceRefresh
    )

    $cacheKey = "App|$ClientId|$TenantId"
    if (-not $ForceRefresh -and $TokenCache.ContainsKey($cacheKey)) {
        $cached = $TokenCache[$cacheKey]
        if ($cached.ExpiresOn -gt (Get-Date).AddMinutes(5)) {
            Write-Verbose "Returning cached app token (expires: $($cached.ExpiresOn))"
            return $cached
        }
    }

    # Acquire new token
    Write-Verbose "Acquiring new app token..."
    $tokenResponse = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -ClientSecret $ClientSecret -Scopes "https://outlook.office365.com/.default" -ErrorAction Stop

    $obj = [PSCustomObject]@{
        AccessToken = $tokenResponse.AccessToken
        ExpiresOn = $tokenResponse.ExpiresOn
        Timestamp = Get-Date
    }

    if (-not $cacheKey) { throw "Invalid cache key." }
    $TokenCache[$cacheKey] = $obj
    Write-Verbose "App token cached (expires: $($obj.ExpiresOn))"
    return $obj
}

function Get-DelegatedToken {
    <#
    .SYNOPSIS
        Acquire or retrieve cached delegated token via credentials (preferred), silent refresh, or interactive fallback.
    .PARAMETER ClientId
        Azure AD application (client) ID.
    .PARAMETER TenantId
        Azure AD tenant ID.
    .PARAMETER Credential
        PSCredential object for the service user (e.g., from Get-Credential).
    .PARAMETER LoginHint
        User principal name for login hint (used if Credential not provided).
    .PARAMETER Silent
        Attempt silent acquisition (non-interactive) first.
    .PARAMETER ForceRefresh
        Force refresh ignoring cache.
    .OUTPUTS
        PSObject with: AccessToken, ExpiresOn, Timestamp
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [string] $ClientId,
        [Parameter(Mandatory=$true)] [string] $TenantId,
        [Parameter(Mandatory=$false)] [PSCredential] $Credential,
        [Parameter(Mandatory=$false)] [string] $LoginHint,
        [switch] $Silent,
        [switch] $ForceRefresh
    )

    # Use Credential username as LoginHint if not provided
    if ($Credential -and -not $LoginHint) {
        $LoginHint = $Credential.UserName
    }
    if (-not $LoginHint) { throw "Either Credential or LoginHint is required." }

    $cacheKey = "Del|$ClientId|$TenantId|$LoginHint"
    if (-not $ForceRefresh -and $TokenCache.ContainsKey($cacheKey)) {
        $cached = $TokenCache[$cacheKey]
        if ($cached.ExpiresOn -gt (Get-Date).AddMinutes(5)) {
            Write-Verbose "Returning cached delegated token (expires: $($cached.ExpiresOn))"
            return $cached
        }
    }

    try {
        Write-Verbose "Acquiring delegated token..."
        $scopes = @("https://outlook.office365.com/EWS.AccessAsUser.All")

        if ($Silent) {
            # Silent refresh attempt
            $tokenResponse = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $scopes -LoginHint $LoginHint -Silent -ErrorAction Stop
        } elseif ($Credential) {
            # Use credentials for non-interactive
            $tokenResponse = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $scopes -UserCredential $Credential -ErrorAction Stop
        } else {
            # Fallback to interactive
            $tokenResponse = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $scopes -LoginHint $LoginHint -Interactive -UseEmbeddedWebView -ErrorAction Stop
        }

        # Force refresh if near expiry
        if ($tokenResponse.ExpiresOn - (Get-Date) -lt (New-TimeSpan -Minutes 5)) {
            Write-Verbose "Token expiring soon; forcing refresh..."
            $tokenResponse = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $scopes -LoginHint $LoginHint -ForceRefresh -ErrorAction Stop
        }
    } catch {
        throw "Delegated token acquisition failed: $_. Fallback: Ensure Credential is valid, or use -Interactive if no credentials provided."
    }

    $obj = [PSCustomObject]@{
        AccessToken = $tokenResponse.AccessToken
        ExpiresOn = $tokenResponse.ExpiresOn
        Timestamp = Get-Date
    }

    if (-not $cacheKey) { throw "Invalid cache key." }
    $TokenCache[$cacheKey] = $obj
    Write-Verbose "Delegated token cached (expires: $($obj.ExpiresOn))"
    return $obj
}

function New-EwsService {
    <#
    .SYNOPSIS
        Create an ExchangeService object with OAuth credentials.
    .PARAMETER AccessToken
        Access token string from Get-AppToken or Get-DelegatedToken.
    .PARAMETER ImpersonatedUser
        SMTP address of mailbox to impersonate (optional).
    .PARAMETER EwsDllPath
        Path to Microsoft.Exchange.WebServices.dll.
    .OUTPUTS
        Microsoft.Exchange.WebServices.Data.ExchangeService
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $AccessToken,
        [Parameter(Mandatory=$false)] [string] $ImpersonatedUser,
        [Parameter(Mandatory=$false)] [string] $EwsDllPath = "Microsoft.Exchange.WebServices.dll"
    )

    if (-not (Test-Path $EwsDllPath)) {
        throw "EWS DLL not found at path $EwsDllPath"
    }

    Add-Type -Path $EwsDllPath -ErrorAction Stop

    $service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2016)
    $service.Url = [Uri]"https://outlook.office365.com/EWS/Exchange.asmx"
    $service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($AccessToken)

    if ($PSBoundParameters.ContainsKey('ImpersonatedUser')) {
        $service.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId(
            [Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $ImpersonatedUser)
    }

    return $service
}

Export-ModuleMember -Function Get-AppToken, Get-DelegatedToken, New-EwsService