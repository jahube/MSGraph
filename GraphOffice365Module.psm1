# GraphOffice365Module.psm1 - PowerShell module for Microsoft Graph queries in Office 365 (Updated July 28, 2025, 6:00 PM CEST)

<#
.SYNOPSIS
Module for interacting with Microsoft Graph API to manage Office 365 user validation errors, license statuses, and user details.

.DESCRIPTION
This module provides functions to authenticate with Microsoft Graph, retrieve user validation errors, check license statuses, display provisioning details, and fetch detailed user information including OU, extension attributes, and proxy addresses. It supports multiple configuration methods: file-based, registry-based, or a single config file.

.PARAMETER ConfigPath
The directory path containing configuration files (e.g., Config_<Company>.json and SECRET_<Company>.txt). Required for file-based mode.

.PARAMETER Company
The company prefix (mandatory) used to name configuration files (e.g., Config_<Company>.json) or registry paths.

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
#>

# Global variables for token caching
$script:AccessToken = $null
$script:TokenExpiry = [DateTime]::MinValue

function Get-GraphToken {
    [CmdletBinding(DefaultParameterSetName = "File")]
    param (
        [Parameter(ParameterSetName = "File", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$ConfigPath,
        [Parameter(Mandatory = $true)]
        [string]$Company,
        [Parameter(ParameterSetName = "File")]
        [Parameter(ParameterSetName = "Registry")]
        [Parameter(ParameterSetName = "ConfigFile")]
        [switch]$SecureLogon,
        [Parameter(ParameterSetName = "Registry")]
        [switch]$Registry,
        [Parameter(ParameterSetName = "ConfigFile", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFile,
        [Parameter(ParameterSetName = "File")]
        [Parameter(ParameterSetName = "Registry")]
        [Parameter(ParameterSetName = "ConfigFile")]
        [object]$ClientSecret  # Optional one-time secret (plain or secure)
    )

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
        if ($PSCmdlet.ParameterSetName -eq "ConfigFile") {
            try {
                $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json -ErrorAction Stop
                $secretFile = if ($config.SecretFilePath) { $config.SecretFilePath } else { $null }
            } catch {
                throw "Failed to read config file $ConfigFile. Ensure it exists and is valid JSON."
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "File") {
            $configPath = $ConfigPath
            $configFile = Join-Path $configPath "Config_$Company.json"
            $secretFile = Join-Path $configPath "SECRET_$Company.txt"
            try {
                if (-not (Test-Path $configFile -PathType Leaf)) {
                    throw "Config file not found: $configFile. Please create it with TenantId and AppId."
                }
                $config = Get-Content $configFile -Raw | ConvertFrom-Json -ErrorAction Stop
            } catch {
                throw "Failed to read config file $configFile. Ensure it exists and is valid JSON."
            }
        } else {
            throw "No valid configuration method specified. Use -ConfigPath, -ConfigFile, or ensure registry is set up."
        }

        # Handle secure logon for client secret (explicitly use file system if -SecureLogon)
        if ($SecureLogon) {
            $secure = Read-Host "Enter Client Secret for $Company" -AsSecureString
            $encrypted = $secure | ConvertFrom-SecureString
            $secure | ConvertFrom-SecureString | Set-Content $secretFile -ErrorAction Stop
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
                throw "No secret found in file system at $secretFile."
            }
            $tenantId = $config.TenantId
            $appId = $config.AppId
            if (-not $tenantId -or -not $appId) {
                throw "Missing TenantId or AppId in config file $configFile."
            }
        } catch {
            throw "Failed to load credentials from file system at $configFile or $secretFile. Error: $_"
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
            if (-not $response.access_token) {
                throw "Token response did not contain an access_token."
            }
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
        if (-not $config.TenantId -or -not $config.AppId) {
            throw "Please provide -TenantId and -AppId when updating ConfigFile."
        }
        $config | ConvertTo-Json -Depth 10 | Set-Content $ConfigFile
        Write-Host "Client Secret encrypted and updated in $ConfigFile" -ForegroundColor Green
    } elseif ($Registry) {
        $regPath = "HKCU:\Software\MSGraph\Credentials\$Company"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        # Update from file if ConfigPath or ConfigFile is specified
        if ($ConfigPath -or $ConfigFile) {
            try {
                $fileConfig = if ($ConfigFile) {
                    Get-Content $ConfigFile -Raw | ConvertFrom-Json -ErrorAction Stop
                } else {
                    Get-Content (Join-Path $ConfigPath "Config_$Company.json") -Raw | ConvertFrom-Json -ErrorAction Stop
                }
                if ($fileConfig.TenantId -and $fileConfig.AppId -and $fileConfig.ClientSecretEnc) {
                    Set-ItemProperty -Path $regPath -Name "TenantId" -Value $fileConfig.TenantId
                    Set-ItemProperty -Path $regPath -Name "AppId" -Value $fileConfig.AppId
                    Set-ItemProperty -Path $regPath -Name "ClientSecret" -Value $fileConfig.ClientSecretEnc
                    Write-Host "Credentials updated in Registry from file system under $regPath" -ForegroundColor Green
                    return
                } else {
                    Write-Host "Missing TenantId, AppId, or ClientSecretEnc in file. Updating only ClientSecret." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Failed to update registry from file system: $_" -ForegroundColor Yellow
            }
        }
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
        if (-not $config.TenantId -or -not $config.AppId) {
            throw "Please provide -TenantId and -AppId when updating file-based config."
        }
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFilePath
        $secure | ConvertFrom-SecureString | Set-Content $secretFile
        Write-Host "Client Secret encrypted and saved to $secretFile" -ForegroundColor Green
    }
}

function Get-GraphUsers {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "File", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$ConfigPath,
        [Parameter(Mandatory = $true)]
        [string]$Company,
        [Parameter(ParameterSetName = "File")]
        [Parameter(ParameterSetName = "Registry")]
        [Parameter(ParameterSetName = "ConfigFile")]
        [switch]$SecureLogon,
        [Parameter(ParameterSetName = "Registry")]
        [switch]$Registry,
        [Parameter(ParameterSetName = "ConfigFile", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFile,
        [string]$LicenseTablePath = "C:\Scripte\LizenzExports_neu\Nicht_entfernen\Product names and service plan identifiers for licensing.csv"
    )

    $token = Get-GraphToken -ConfigPath $ConfigPath -Company $Company -SecureLogon:$SecureLogon -Registry:$Registry -ConfigFile $ConfigFile
    $headers = @{ "Authorization" = "Bearer $token" }

    $url = "https://graph.microsoft.com/beta/users?`$select=displayName,userPrincipalName,mail,signInActivity,userType,assignedLicenses,assignedPlans,LicenseAssignmentStates,LicenseDetails,onPremisesSyncEnabled,jobTitle,city,department,country,companyName,onPremisesDistinguishedName,officeLocation,onPremisesUserPrincipalName,preferredLanguage,proxyAddresses,usageLocation,userType,onPremisesObjectIdentifier,isLicenseReconciliationNeeded,onPremisesSamAccountName,onPremisesExtensionAttributes,givenName,surname,createdDateTime,id&`$expand=manager"
    $GraphExport_RAW = @()

    while ($url -ne $null) {
        $data = (Invoke-WebRequest -Headers $headers -Uri $url) | ConvertFrom-Json
        $GraphExport_RAW += $data.value
        $url = $data.'@odata.nextLink'
    }

    # Load license table
    if (-not (Test-Path $LicenseTablePath)) {
        $licenseTableURL = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'
        try {
            Invoke-WebRequest -Uri $licenseTableURL -OutFile $licenseTablePath
            Write-Host "SKU table downloaded to $licenseTablePath" -ForegroundColor Green
        } catch {
            throw "Failed to download license table. Please ensure $licenseTablePath exists or is accessible."
        }
    }
    $licenseTable = Import-Csv -LiteralPath $LicenseTablePath -Delimiter "," -Encoding UTF8

    # Create hashtables for license and service plan lookup
    $licenseTableHash = @{}
    $serviceplan_identifiers_Hashtable = @{}
    $licenseTable | ForEach-Object {
        $licenseTableHash[$_.GUID] = $_.Product_Display_Name
        $serviceplan_identifiers_Hashtable[$_.String_Id] = $_.Product_Display_Name
    }

    # Process users
    $GraphExport_Processed = $GraphExport_RAW | ForEach-Object {
        $ou = if ($_.onPremisesDistinguishedName) {
            ((($_.onPremisesDistinguishedName -split "," | Where-Object { $_ -match "OU=" }) -replace "OU=")[(($_.onPremisesDistinguishedName -split "," | Where-Object { $_ -match "OU=" }).Count)..0]) -join "/"
        } else { $null }

        $remoteRoutingAddress = if ($_.proxyAddresses) {
            ($_.proxyAddresses | Where-Object { $_ -imatch "^smtp:" }) -replace "^smtp:" | Select-Object -First 1
        } else { $null }

        $onPremisesProxyAddresses = if ($_.PSObject.Properties.Name -contains "onPremisesProxyAddresses") {
            $_.onPremisesProxyAddresses
        } else { $null }

        $extensionAttribute4 = $_.onPremisesExtensionAttributes.extensionAttribute4

        $managerOu = if ($_.manager.onPremisesDistinguishedName) {
            ((($_.manager.onPremisesDistinguishedName -split "," | Where-Object { $_ -match "OU=" }) -replace "OU=")[(($_.manager.onPremisesDistinguishedName -split "," | Where-Object { $_ -match "OU=" }).Count)..0]) -join "/"
        } else { $null }

        [PSCustomObject]@{
            DisplayName                  = $_.displayName
            UserPrincipalName            = $_.userPrincipalName
            Mail                         = $_.mail
            LastSignInDateTime           = $_.signInActivity.lastSignInDateTime
            LastNonInteractiveSignInDateTime = $_.signInActivity.lastNonInteractiveSignInDateTime
            UserType                     = $_.userType
            AssignedLicenses             = $_.assignedLicenses
            AssignedPlans                = $_.assignedPlans
            LicenseAssignmentStates      = $_.LicenseAssignmentStates
            LicenseDetails               = $_.LicenseDetails
            OnPremisesSyncEnabled        = $_.onPremisesSyncEnabled
            JobTitle                     = $_.jobTitle
            City                         = $_.city
            Department                   = $_.department
            Country                      = $_.country
            CompanyName                  = $_.companyName
            OnPremisesDistinguishedName  = $_.onPremisesDistinguishedName
            OfficeLocation               = $_.officeLocation
            OnPremisesUserPrincipalName  = $_.onPremisesUserPrincipalName
            PreferredLanguage            = $_.preferredLanguage
            ProxyAddresses               = $_.proxyAddresses
            UsageLocation                = $_.usageLocation
            OnPremisesObjectIdentifier   = $_.onPremisesObjectIdentifier
            IsLicenseReconciliationNeeded = $_.isLicenseReconciliationNeeded
            OnPremisesSamAccountName     = $_.onPremisesSamAccountName
            ExtensionAttribute4          = $extensionAttribute4
            OU                           = $ou
            RemoteRoutingAddress         = $remoteRoutingAddress
            OnPremisesProxyAddresses     = $onPremisesProxyAddresses
            Manager                      = $_.manager.displayName
            ManagerUPN                   = $_.manager.userPrincipalName
            ManagerOU                    = $managerOu
            LicenseDisplayNames          = ($_.assignedLicenses | Where-Object { $_.skuId } | ForEach-Object { $licenseTableHash[$_.skuId] }) -join "; "
            ServicePlanDisplayNames      = ($_.assignedPlans | Where-Object { $_.servicePlanId } | ForEach-Object { $serviceplan_identifiers_Hashtable[$_.servicePlanId] }) -join "; "
            Id                           = $_.id
            CreatedDateTime              = $_.createdDateTime
        }
    }

    return $GraphExport_Processed
}

function Get-LicenseStatus {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "File", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$ConfigPath,
        [Parameter(Mandatory = $true)]
        [string]$Company,
        [Parameter(ParameterSetName = "File")]
        [Parameter(ParameterSetName = "Registry")]
        [Parameter(ParameterSetName = "ConfigFile")]
        [switch]$SecureLogon,
        [Parameter(ParameterSetName = "Registry")]
        [switch]$Registry,
        [Parameter(ParameterSetName = "ConfigFile", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFile,
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        [switch]$All,
        [switch]$ShowProvisioningStatus
    )

    $token = Get-GraphToken -ConfigPath $ConfigPath -Company $Company -SecureLogon:$SecureLogon -Registry:$Registry -ConfigFile $ConfigFile
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
        $users = Get-GraphUsers -ConfigPath $ConfigPath -Company $Company -SecureLogon:$SecureLogon -Registry:$Registry -ConfigFile $ConfigFile
        foreach ($user in $users) {
            $uri = "https://graph.microsoft.com/v1.0/users/$($user.Id)/licenseDetails"
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
                        UserPrincipalName = $user.UserPrincipalName
                        Id = $user.Id
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
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "File", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$ConfigPath,
        [Parameter(Mandatory = $true)]
        [string]$Company,
        [Parameter(ParameterSetName = "File")]
        [Parameter(ParameterSetName = "Registry")]
        [Parameter(ParameterSetName = "ConfigFile")]
        [switch]$SecureLogon,
        [Parameter(ParameterSetName = "Registry")]
        [switch]$Registry,
        [Parameter(ParameterSetName = "ConfigFile", Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFile,
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        [switch]$All
    )

    $token = Get-GraphToken -ConfigPath $ConfigPath -Company $Company -SecureLogon:$SecureLogon -Registry:$Registry -ConfigFile $ConfigFile
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

Export-ModuleMember -Function Get-GraphToken, Set-ClientSecret, Get-UserValidationErrors, Get-LicenseStatus, Get-ProvisioningErrors, Show-LicenseProvisioningStatus