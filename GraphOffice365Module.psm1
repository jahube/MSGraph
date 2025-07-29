# GraphOffice365Module.psm1 - PowerShell module for Microsoft Graph queries in Office 365 (Updated July 29, 2025, 10:30 AM CEST)

<#
.SYNOPSIS
Module for interacting with Microsoft Graph API to manage Office 365 user validation errors, license statuses, and user details.

.DESCRIPTION
This module provides functions to authenticate with Microsoft Graph, retrieve user validation errors, check license statuses, display provisioning details, and fetch detailed user information including OU, extension attributes, and proxy addresses. It supports multiple configuration methods: file-based, registry-based, or a single config file.

.PARAMETER ConfigPath
The directory path containing configuration files (e.g., Config_<Company>.json and SECRET_<Company>.txt). Required for file-based mode.

.PARAMETER Company
The company prefix used to name configuration files (e.g., Config_<Company>.json) or registry paths. Required if no token is provided.

.PARAMETER SecureLogon
Prompts for a new ClientSecret and saves it encrypted to the chosen storage method (file, registry, or config file).

.PARAMETER Registry
Uses the Windows Registry (HKCU:\Software\MSGraph\Credentials\<Company>) to store the encrypted ClientSecret, TenantId, and AppId.

.PARAMETER ConfigFile
The full path to a single JSON configuration file containing TenantId, AppId, and optionally ClientSecretEnc or SecretFilePath.

.PARAMETER ClientSecret
Optional plain or secure client secret for one-time use in Get-GraphToken or setting via Set-ClientSecret (without storage unless specified).

.EXAMPLE
Get-GraphToken -Company "ELKW"
Automatically pulls credentials from registry, falling back to file system if not found.

.EXAMPLE
Get-GraphToken -ConfigPath "C:\Scripte\config" -Company "ELKW" -SecureLogon
Sets up an encrypted ClientSecret in the file system for troubleshooting.

.EXAMPLE
Get-GraphToken -Registry -Company "ELKW"
Uses registry credentials for authentication.

.EXAMPLE
Get-GraphToken -ConfigFile "C:\Scripte\config\myconfig.json"
Uses a specific config file for authentication.

.EXAMPLE
Get-GraphToken -Company "ELKW" -ClientSecret "mySuperSecretValue123"
Uses a plain client secret for one-time authentication without storage.

.EXAMPLE
Set-GraphConfig -ConfigPath "C:\Scripte\config"
Sets the default credential type to ConfigPath.

.EXAMPLE
Set-GraphConfig -Registry
Sets the default credential type to Registry.

.EXAMPLE
Get-LicenseStatus -Identity "Alexandra.Komar-Pristl@mav.elkw.de" -ShowProvisioningStatus
Uses default config if set, without requiring -Company.

.EXAMPLE
$token = Get-GraphToken -Company "ELKW" -Registry
Get-LicenseStatus -Identity "Alexandra.Komar-Pristl@mav.elkw.de" -ShowProvisioningStatus -Token $token
Uses the provided token if not expired.
#>

# Global variables for token caching and default config
$script:AccessToken = $null
$script:TokenExpiry = [DateTime]::MinValue
$script:DefaultCredentialType = $null
$script:DefaultConfigPath = $null

# Load default config from registry on module load
$configRegPath = "HKCU:\Software\MSGraph\Config"
if (Test-Path $configRegPath) {
    $regData = Get-ItemProperty -Path $configRegPath -ErrorAction SilentlyContinue
    $script:DefaultCredentialType = $regData.CredentialType
    $script:DefaultConfigPath = $regData.ConfigPath
}

function Set-GraphConfig {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "ConfigPath", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$ConfigPath,
        [Parameter(ParameterSetName = "Registry", Mandatory = $true)]
        [switch]$Registry
    )

    $configRegPath = "HKCU:\Software\MSGraph\Config"
    if (-not (Test-Path $configRegPath)) { New-Item -Path $configRegPath -Force | Out-Null }

    if ($PSCmdlet.ParameterSetName -eq "ConfigPath") {
        Set-ItemProperty -Path $configRegPath -Name "CredentialType" -Value "ConfigPath"
        Set-ItemProperty -Path $configRegPath -Name "ConfigPath" -Value $ConfigPath
        $script:DefaultCredentialType = "ConfigPath"
        $script:DefaultConfigPath = $ConfigPath
        Write-Host "Default credential type set to ConfigPath with path $ConfigPath." -ForegroundColor Green
    } elseif ($PSCmdlet.ParameterSetName -eq "Registry") {
        Set-ItemProperty -Path $configRegPath -Name "CredentialType" -Value "Registry"
        Set-ItemProperty -Path $configRegPath -Name "ConfigPath" -Value $null
        $script:DefaultCredentialType = "Registry"
        $script:DefaultConfigPath = $null
        Write-Host "Default credential type set to Registry." -ForegroundColor Green
    }
}

function Get-GraphToken {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(ParameterSetName = "File")]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$ConfigPath,
        [Parameter(ParameterSetName = "File")]
        [Parameter(ParameterSetName = "Registry")]
        [Parameter(ParameterSetName = "ConfigFile")]
        [string]$Company,
        [Parameter(ParameterSetName = "File")]
        [Parameter(ParameterSetName = "Registry")]
        [Parameter(ParameterSetName = "ConfigFile")]
        [switch]$SecureLogon,
        [Parameter(ParameterSetName = "Registry")]
        [switch]$Registry,
        [Parameter(ParameterSetName = "ConfigFile")]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFile,
        [Parameter(ParameterSetName = "File")]
        [Parameter(ParameterSetName = "Registry")]
        [Parameter(ParameterSetName = "ConfigFile")]
        [object]$ClientSecret,
        [Parameter(ParameterSetName = "Token")]
        [string]$Token
    )

    # Use default credential type if not specified
    if (-not $ConfigPath -and -not $Registry -and -not $ConfigFile -and -not $Token) {
        if ($script:DefaultCredentialType -eq "ConfigPath" -and $script:DefaultConfigPath) {
            $ConfigPath = $script:DefaultConfigPath
        } elseif ($script:DefaultCredentialType -eq "Registry") {
            $Registry = $true
        } else {
            if (-not $Company) {
                throw "No default config set and no Company specified. Use Set-GraphConfig to set a default or provide -Company."
            }
        }
    }

    # Use provided token if valid and not expired
    if ($Token) {
        if (-not $script:AccessToken -or $script:TokenExpiry -le [DateTime]::UtcNow) {
            $script:AccessToken = $Token
            $script:TokenExpiry = [DateTime]::UtcNow.AddHours(1) # Assume 1-hour token validity for simplicity
        }
        return $script:AccessToken
    }

    # Validate that at least one storage method is specified if no token
    if (-not ($ConfigPath -or $Registry -or $ConfigFile)) {
        throw "Please specify either -ConfigPath, -Registry, or -ConfigFile to define the configuration source."
    }

    # Check registry first when -Company is provided
    $regPath = "HKCU:\Software\MSGraph\Credentials\$Company"
    $tenantId = $null
    $appId = $null
    $clientSecretPlain = $null
    if ($Company -and -not $SecureLogon -and ($Registry -or (Test-Path $regPath))) {
        try {
            if (Test-Path $regPath) {
                $regData = Get-ItemProperty -Path $regPath -ErrorAction Stop
                $tenantId = $regData.TenantId
                $appId = $regData.AppId
                $encryptedSecret = $regData.ClientSecret
                if ($encryptedSecret) {
                    $secure = $encryptedSecret | ConvertTo-SecureString
                    $clientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
                    )
                }
                Write-Verbose "Loaded credentials from registry at $regPath"
            }
        } catch {
            Write-Warning "Failed to load credentials from registry at $regPath. Falling back to file system."
        }
    }

    # Fall back to file system if registry data is incomplete or -SecureLogon is used
    if ((-not $tenantId -or -not $appId -or -not $clientSecretPlain) -or $SecureLogon) {
        if ($ConfigFile) {
            $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            $secretFile = if ($config.SecretFilePath) { $config.SecretFilePath } else { $null }
        } else {
            $configPath = if ($ConfigPath) { $ConfigPath } else { "C:\Scripte\config" }
            $configFile = Join-Path $configPath "Config_$Company.json"
            if (-not (Test-Path $configFile -PathType Leaf)) {
                throw "Config file not found: $configFile. Please create it with TenantId and AppId."
            }
            $config = Get-Content $configFile -Raw | ConvertFrom-Json
            $secretFile = Join-Path $configPath "SECRET_$Company.txt"
        }

        # Handle secure logon for client secret (explicitly use file system if -SecureLogon)
        if ($SecureLogon) {
            $secure = Read-Host "Enter Client Secret for $Company" -AsSecureString
            $encrypted = $secure | ConvertFrom-SecureString
            $secure | ConvertFrom-SecureString | Set-Content $secretFile
            Write-Host "Client Secret encrypted and saved to $secretFile for troubleshooting" -ForegroundColor Green
        }

        # Load from file system
        try {
            if ($config.ClientSecretEnc) {
                $clientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                        ($config.ClientSecretEnc | ConvertTo-SecureString)
                    )
                )
            } elseif (Test-Path $secretFile) {
                $encrypted = Get-Content $secretFile | ConvertTo-SecureString
                $clientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encrypted)
                )
            } else {
                throw "No secret found in file system."
            }
            $tenantId = $config.TenantId
            $appId = $config.AppId
        } catch {
            throw "Failed to load credentials from file system at $configFile or $secretFile. Ensure files exist and are accessible."
        }
    }

    # Use provided one-time secret if available
    if ($ClientSecret) {
        if ($ClientSecret -is [System.Security.SecureString]) {
            $clientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
            )
        } elseif ($ClientSecret -is [string]) {
            $clientSecretPlain = $ClientSecret
        } else {
            throw "ClientSecret must be a SecureString or string."
        }
        Write-Host "Using provided one-time Client Secret (not stored)." -ForegroundColor Yellow
    }

    if (-not $tenantId -or -not $appId -or -not $clientSecretPlain) {
        throw "Missing required credentials (TenantId, AppId, or ClientSecret). Please configure them using -SecureLogon or provide via -ClientSecret."
    }

    if (-not $script:AccessToken -or $script:TokenExpiry -le [DateTime]::UtcNow.AddMinutes(5)) {
        $body = @{
            grant_type = "client_credentials"
            client_id = $appId
            client_secret = $clientSecretPlain
            scope = "https://graph.microsoft.com/.default"
        }
        $uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
        try {
            $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            $script:AccessToken = $response.access_token
            $script:TokenExpiry = [DateTime]::UtcNow.AddSeconds($response.expires_in)
        } catch {
            throw "Failed to obtain access token. Check credentials and network connectivity. Error: $_"
        }
    }

    return $script:AccessToken
}

function Set-ClientSecret {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "File", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$ConfigPath,
        [Parameter(Mandatory = $true, ParameterSetName = "File")]
        [Parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [Parameter(Mandatory = $true, ParameterSetName = "ConfigFile")]
        [string]$Company,
        [Parameter(ParameterSetName = "File")]
        [Parameter(ParameterSetName = "Registry")]
        [Parameter(ParameterSetName = "ConfigFile")]
        [switch]$SecureLogon,
        [Parameter(ParameterSetName = "Registry", Mandatory = $true)]
        [switch]$Registry,
        [Parameter(ParameterSetName = "ConfigFile", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFile,
        [Parameter()]
        [object]$ClientSecret,
        [Parameter(ParameterSetName = "Registry")]
        [string]$TenantId,
        [Parameter(ParameterSetName = "Registry")]
        [string]$AppId
    )

    # Validate that at least one storage method is specified
    if (-not ($ConfigPath -or $Registry -or $ConfigFile)) {
        throw "Please specify either -ConfigPath, -Registry, or -ConfigFile to define the storage location for the Client Secret."
    }

    # Determine secure string from input or prompt
    if (-not $ClientSecret -and -not $SecureLogon) {
        if ($PSCmdlet.ParameterSetName -eq "ConfigFile") {
            $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($config -and $config.ClientSecretEnc) {
                $ClientSecret = $config.ClientSecretEnc | ConvertTo-SecureString
            }
        } elseif (Test-Path (Join-Path $ConfigPath "SECRET_$Company.txt")) {
            $ClientSecret = (Get-Content (Join-Path $ConfigPath "SECRET_$Company.txt") | ConvertTo-SecureString)
        }
        if (-not $ClientSecret) {
            Write-Host "Please provide -ClientSecret or use -SecureLogon to set it." -ForegroundColor Yellow
            return
        }
    }

    if ($SecureLogon -or -not $ClientSecret) {
        $secure = Read-Host "Enter new Client Secret for $Company" -AsSecureString
    } else {
        if ($ClientSecret -is [System.Security.SecureString]) {
            $secure = $ClientSecret
        } else {
            $secure = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        }
    }

    $encrypted = $secure | ConvertFrom-SecureString

    if ($PSCmdlet.ParameterSetName -eq "ConfigFile") {
        $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        if (-not $config) { $config = @{ TenantId = $null; AppId = $null; ClientSecretEnc = $null } }
        $config.ClientSecretEnc = $encrypted
        if ($TenantId) { $config.TenantId = $TenantId }
        if ($AppId) { $config.AppId = $AppId }
        $config | ConvertTo-Json -Depth 10 | Set-Content $ConfigFile
        Write-Host "Client Secret encrypted and updated in $ConfigFile" -ForegroundColor Green
    } elseif ($Registry) {
        $regPath = "HKCU:\Software\MSGraph\Credentials\$Company"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "ClientSecret" -Value $encrypted
        if ($TenantId) { Set-ItemProperty -Path $regPath -Name "TenantId" -Value $TenantId }
        if ($AppId) { Set-ItemProperty -Path $regPath -Name "AppId" -Value $AppId }
        Write-Host "Client Secret encrypted and saved to Registry under $regPath" -ForegroundColor Green
    } else {
        $secretFile = Join-Path $ConfigPath "SECRET_$Company.txt"
        $configFilePath = Join-Path $ConfigPath "Config_$Company.json"
        $config = Get-Content $configFilePath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        if (-not $config) { $config = @{ TenantId = $null; AppId = $null; ClientSecretEnc = $null } }
        $config.ClientSecretEnc = $encrypted
        if ($TenantId) { $config.TenantId = $TenantId }
        if ($AppId) { $config.AppId = $AppId }
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFilePath
        $secure | ConvertFrom-SecureString | Set-Content $secretFile
        Write-Host "Client Secret encrypted and saved to $secretFile" -ForegroundColor Green
    }
}

function Get-UserValidationErrors {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "ConfigBased")]
        [Parameter(Mandatory = $true, ParameterSetName = "TokenBased")]
        [string]$Identity,

        [Parameter(ParameterSetName = "ConfigBased")]
        [string]$Company,

        [Parameter(ParameterSetName = "ConfigBased")]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$ConfigPath,

        [Parameter(ParameterSetName = "ConfigBased")]
        [switch]$Registry,

        [Parameter(ParameterSetName = "ConfigBased")]
        [switch]$SecureLogon,

        [Parameter(ParameterSetName = "ConfigBased")]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFile,

        [Parameter(Mandatory = $true, ParameterSetName = "TokenBased")]
        [string]$Token,

        [Parameter(ParameterSetName = "ConfigBased")]
        [Parameter(ParameterSetName = "TokenBased")]
        [switch]$All
    )

    $token = if ($PSCmdlet.ParameterSetName -eq "TokenBased") {
        $Token
    } else {
        if (-not $Company) {
            throw "Company is required for config-based authentication."
        }
        Get-GraphToken -ConfigPath $ConfigPath -Company $Company -SecureLogon:$SecureLogon -Registry:$Registry -ConfigFile $ConfigFile
    }
    $headers = @{ "Authorization" = "Bearer $token" }

    $errorsList = @()

    if ($Identity) {
        $uri = "https://graph.microsoft.com/v1.0/users/$Identity`?`$select=id,userPrincipalName,serviceProvisioningErrors"
        $user = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        if ($user.serviceProvisioningErrors -and $user.serviceProvisioningErrors.Count -gt 0) {
            foreach ($err in $user.serviceProvisioningErrors) {
                $parsedDetail = if ($err.errorDetail) {
                    ([xml]$err.errorDetail).ServiceInstance.ObjectErrors.ErrorRecord | ForEach-Object {
                        [PSCustomObject]@{
                            ErrorCode = $_.ErrorCode
                            ErrorDescription = $_.ErrorDescription
                        }
                    }
                } else { $null }
                $errorsList += [PSCustomObject]@{
                    UserPrincipalName = $user.userPrincipalName
                    Id = $user.id
                    CreatedDateTime = $err.createdDateTime
                    IsResolved = $err.isResolved
                    ServiceInstance = $err.serviceInstance
                    ErrorDetail = $parsedDetail
                }
            }
        }
    } elseif ($All) {
        $uri = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,serviceProvisioningErrors&`$top=999"
        do {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
            $response.value | Where-Object { $_.serviceProvisioningErrors -and $_.serviceProvisioningErrors.Count -gt 0 } | ForEach-Object {
                foreach ($err in $_.serviceProvisioningErrors) {
                    $parsedDetail = if ($err.errorDetail) {
                        ([xml]$err.errorDetail).ServiceInstance.ObjectErrors.ErrorRecord | ForEach-Object {
                            [PSCustomObject]@{
                                ErrorCode = $_.ErrorCode
                                ErrorDescription = $_.ErrorDescription
                            }
                        }
                    } else { $null }
                    $errorsList += [PSCustomObject]@{
                        UserPrincipalName = $_.userPrincipalName
                        Id = $_.id
                        CreatedDateTime = $err.createdDateTime
                        IsResolved = $err.isResolved
                        ServiceInstance = $err.serviceInstance
                        ErrorDetail = $parsedDetail
                    }
                }
            }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
    }

    return $errorsList
}

function Get-LicenseStatus {
    [CmdletBinding(DefaultParameterSetName = "ConfigBased")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "ConfigBased")]
        [Parameter(Mandatory = $true, ParameterSetName = "TokenBased")]
        [string]$Identity,

        [Parameter(ParameterSetName = "ConfigBased")]
        [string]$Company,

        [Parameter(ParameterSetName = "ConfigBased")]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$ConfigPath,

        [Parameter(ParameterSetName = "ConfigBased")]
        [switch]$Registry,

        [Parameter(ParameterSetName = "ConfigBased")]
        [switch]$SecureLogon,

        [Parameter(ParameterSetName = "ConfigBased")]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFile,

        [Parameter(Mandatory = $true, ParameterSetName = "TokenBased")]
        [string]$Token,

        [Parameter(ParameterSetName = "ConfigBased")]
        [Parameter(ParameterSetName = "TokenBased")]
        [switch]$All,

        [Parameter(ParameterSetName = "ConfigBased")]
        [Parameter(ParameterSetName = "TokenBased")]
        [switch]$ShowProvisioningStatus
    )

    $token = if ($PSCmdlet.ParameterSetName -eq "TokenBased") {
        $Token
    } else {
        if (-not $Company) {
            throw "Company is required for config-based authentication."
        }
        Get-GraphToken -ConfigPath $ConfigPath -Company $Company -SecureLogon:$SecureLogon -Registry:$Registry -ConfigFile $ConfigFile
    }
    $headers = @{ "Authorization" = "Bearer $token" }

    $licenseList = @()

    if ($Identity) {
        $uri = "https://graph.microsoft.com/v1.0/users/$Identity/licenseDetails"
        try {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            $licenses = $response.value | ForEach-Object {
                $provDetails = if ($ShowProvisioningStatus) {
                    foreach ($plan in $_.servicePlans) {
                        [PSCustomObject]@{
                            ServicePlanName    = $plan.servicePlanName
                            ProvisioningStatus = $plan.provisioningStatus
                            AppliesTo          = $plan.appliesTo
                        }
                    }
                } else { $null }
                [PSCustomObject]@{
                    SkuPartNumber = $_.skuPartNumber
                    SkuId = $_.skuId
                    ProvisioningDetails = $provDetails
                }
            }
            $licenseList += [PSCustomObject]@{
                Identity = $Identity
                Licenses = $licenses
            }
        } catch {
            Write-Warning "Failed to retrieve license details for $Identity. Error: $_"
        }
    } elseif ($All) {
        $usersUri = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName&`$top=999"
        $users = @()
        do {
            try {
                $userResponse = Invoke-RestMethod -Uri $usersUri -Headers $headers -Method Get -ErrorAction Stop
                $users += $userResponse.value
                $usersUri = $userResponse.'@odata.nextLink'
            } catch {
                Write-Warning "Failed to retrieve user list. Error: $_"
                break
            }
        } while ($usersUri)

        foreach ($user in $users) {
            $uri = "https://graph.microsoft.com/v1.0/users/$($user.id)/licenseDetails"
            try {
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                $licenses = $response.value | ForEach-Object {
                    $provDetails = if ($ShowProvisioningStatus) {
                        foreach ($plan in $_.servicePlans) {
                            [PSCustomObject]@{
                                ServicePlanName    = $plan.servicePlanName
                                ProvisioningStatus = $plan.provisioningStatus
                                AppliesTo          = $plan.appliesTo
                            }
                        }
                    } else { $null }
                    [PSCustomObject]@{
                        SkuPartNumber = $_.skuPartNumber
                        SkuId = $_.skuId
                        ProvisioningDetails = $provDetails
                    }
                }
                if ($licenses) {
                    $licenseList += [PSCustomObject]@{
                        UserPrincipalName = $user.userPrincipalName
                        Id = $user.id
                        Licenses = $licenses
                    }
                }
            } catch {
                Write-Warning "Failed to retrieve license details for $($user.UserPrincipalName). Error: $_"
            }
        }
    }

    # Note: If exporting to JSON, use -Depth 4+ to avoid stringified nested objects, e.g., $licenseList | ConvertTo-Json -Depth 4
    return $licenseList
}

function Get-ProvisioningErrors {
    [CmdletBinding(DefaultParameterSetName = "ConfigBased")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "ConfigBased")]
        [Parameter(Mandatory = $true, ParameterSetName = "TokenBased")]
        [string]$Identity,

        [Parameter(ParameterSetName = "ConfigBased")]
        [string]$Company,

        [Parameter(ParameterSetName = "ConfigBased")]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$ConfigPath,

        [Parameter(ParameterSetName = "ConfigBased")]
        [switch]$Registry,

        [Parameter(ParameterSetName = "ConfigBased")]
        [switch]$SecureLogon,

        [Parameter(ParameterSetName = "ConfigBased")]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFile,

        [Parameter(Mandatory = $true, ParameterSetName = "TokenBased")]
        [string]$Token,

        [Parameter(ParameterSetName = "ConfigBased")]
        [Parameter(ParameterSetName = "TokenBased")]
        [switch]$All
    )

    $token = if ($PSCmdlet.ParameterSetName -eq "TokenBased") {
        $Token
    } else {
        if (-not $Company) {
            throw "Company is required for config-based authentication."
        }
        Get-GraphToken -ConfigPath $ConfigPath -Company $Company -SecureLogon:$SecureLogon -Registry:$Registry -ConfigFile $ConfigFile
    }
    $headers = @{ "Authorization" = "Bearer $token" }

    $errorsList = @()

    if ($Identity) {
        # Get license provisioning errors
        $uri = "https://graph.microsoft.com/v1.0/users/$Identity/licenseDetails"
        try {
            $licenseResponse = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            $licenseErrors = $licenseResponse.value | ForEach-Object {
                $license = $_.skuPartNumber
                $failedPlans = $_.servicePlans | Where-Object { $_.provisioningStatus -ne 'Success' } | ForEach-Object {
                    [PSCustomObject]@{
                        Type              = "LicenseProvisioning"
                        User              = $Identity
                        License           = $license
                        ServicePlanName   = $_.servicePlanName
                        ProvisioningStatus = $_.provisioningStatus
                        AppliesTo         = $_.appliesTo
                    }
                }
                $failedPlans
            }
        } catch {
            Write-Warning "Failed to retrieve license details for $Identity. Error: $_"
        }

        # Get validation errors
        $uri = "https://graph.microsoft.com/v1.0/users/$Identity`?`$select=id,userPrincipalName,serviceProvisioningErrors"
        try {
            $user = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            $validationErrors = if ($user.serviceProvisioningErrors -and $user.serviceProvisioningErrors.Count -gt 0) {
                foreach ($err in $user.serviceProvisioningErrors) {
                    $parsedDetail = if ($err.errorDetail) {
                        ([xml]$err.errorDetail).ServiceInstance.ObjectErrors.ErrorRecord | ForEach-Object {
                            [PSCustomObject]@{
                                ErrorCode = $_.ErrorCode
                                ErrorDescription = $_.ErrorDescription
                            }
                        }
                    } else { $null }
                    [PSCustomObject]@{
                        Type              = "ValidationError"
                        User              = $user.userPrincipalName
                        License           = $null
                        ServicePlanName   = $null
                        ProvisioningStatus = $null
                        AppliesTo         = $null
                        CreatedDateTime   = $err.createdDateTime
                        IsResolved        = $err.isResolved
                        ServiceInstance   = $err.serviceInstance
                        ErrorDetail       = $parsedDetail
                    }
                }
            }
        } catch {
            Write-Warning "Failed to retrieve validation errors for $Identity. Error: $_"
        }

        $errorsList += $licenseErrors
        $errorsList += $validationErrors
    } elseif ($All) {
        $usersUri = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName&`$top=999"
        $users = @()
        do {
            try {
                $userResponse = Invoke-RestMethod -Uri $usersUri -Headers $headers -Method Get -ErrorAction Stop
                $users += $userResponse.value
                $usersUri = $userResponse.'@odata.nextLink'
            } catch {
                Write-Warning "Failed to retrieve user list. Error: $_"
                break
            }
        } while ($usersUri)

        foreach ($user in $users) {
            $uri = "https://graph.microsoft.com/v1.0/users/$($user.id)/licenseDetails"
            try {
                $licenseResponse = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                $licenseErrors = $licenseResponse.value | ForEach-Object {
                    $license = $_.skuPartNumber
                    $failedPlans = $_.servicePlans | Where-Object { $_.provisioningStatus -ne 'Success' } | ForEach-Object {
                        [PSCustomObject]@{
                            Type              = "LicenseProvisioning"
                            User              = $user.userPrincipalName
                            License           = $license
                            ServicePlanName   = $_.servicePlanName
                            ProvisioningStatus = $_.provisioningStatus
                            AppliesTo         = $_.appliesTo
                        }
                    }
                    $failedPlans
                }
            } catch {
                Write-Warning "Failed to retrieve license details for $($user.userPrincipalName). Error: $_"
            }

            $uri = "https://graph.microsoft.com/v1.0/users/$($user.id)`?`$select=id,userPrincipalName,serviceProvisioningErrors"
            try {
                $userData = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                $validationErrors = if ($userData.serviceProvisioningErrors -and $userData.serviceProvisioningErrors.Count -gt 0) {
                    foreach ($err in $userData.serviceProvisioningErrors) {
                        $parsedDetail = if ($err.errorDetail) {
                            ([xml]$err.errorDetail).ServiceInstance.ObjectErrors.ErrorRecord | ForEach-Object {
                                [PSCustomObject]@{
                                    ErrorCode = $_.ErrorCode
                                    ErrorDescription = $_.ErrorDescription
                                }
                            }
                        } else { $null }
                        [PSCustomObject]@{
                            Type              = "ValidationError"
                            User              = $userData.userPrincipalName
                            License           = $null
                            ServicePlanName   = $null
                            ProvisioningStatus = $null
                            AppliesTo         = $null
                            CreatedDateTime   = $err.createdDateTime
                            IsResolved        = $err.isResolved
                            ServiceInstance   = $err.serviceInstance
                            ErrorDetail       = $parsedDetail
                        }
                    }
                }
            } catch {
                Write-Warning "Failed to retrieve validation errors for $($user.userPrincipalName). Error: $_"
            }

            $errorsList += $licenseErrors
            $errorsList += $validationErrors
        }
    }

    return $errorsList
}

function Show-LicenseProvisioningStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]$LicenseStatus
    )

    process {
        $licenses = $LicenseStatus.Licenses
        if ($licenses) {
            foreach ($license in $licenses) {
                Write-Host "`nLicense: $($license.SkuPartNumber)" -ForegroundColor Cyan

                foreach ($plan in $license.ProvisioningDetails) {
                    $status = $plan.ProvisioningStatus

                    switch ($status) {
                        'Success' {
                            Write-Host ("  ✔ {0,-35} {1,-20} {2}" -f $plan.ServicePlanName, $status, $plan.AppliesTo) -ForegroundColor Green
                        }
                        'PendingProvisioning' {
                            Write-Host ("  ⚠ {0,-35} {1,-20} {2}" -f $plan.ServicePlanName, $status, $plan.AppliesTo) -ForegroundColor Yellow
                        }
                        'Disabled' {
                            Write-Host ("  ✖ {0,-35} {1,-20} {2}" -f $plan.ServicePlanName, $status, $plan.AppliesTo) -ForegroundColor DarkGray
                        }
                        'PendingInput' {
                            Write-Host ("  ❗ {0,-35} {1,-20} {2}" -f $plan.ServicePlanName, $status, $plan.AppliesTo) -ForegroundColor Magenta
                        }
                        'Error' {
                            Write-Host ("  ❌ {0,-35} {1,-20} {2}" -f $plan.ServicePlanName, $status, $plan.AppliesTo) -ForegroundColor Red
                        }
                        Default {
                            Write-Host ("  ?  {0,-35} {1,-20} {2}" -f $plan.ServicePlanName, $status, $plan.AppliesTo) -ForegroundColor White
                        }
                    }
                }
            }
        } else {
            Write-Host "No license details available for this user." -ForegroundColor Yellow
        }
    }
}

Export-ModuleMember -Function Get-GraphToken, Set-ClientSecret, Get-UserValidationErrors, Get-LicenseStatus, Get-ProvisioningErrors, Show-LicenseProvisioningStatus, Set-GraphConfig