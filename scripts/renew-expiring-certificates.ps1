# Renew Expiring TLS Certificates in Kubernetes Namespace

param(
    [Parameter(Mandatory=$false)]
    [string]$Namespace = "",
    
    [Parameter(Mandatory=$true)]
    [string]$KeyVaultName,
    
    [Parameter(Mandatory=$true)]
    [string]$CertificateSecretName,

    [Parameter(Mandatory=$true)]
    [string]$KeySecretName,
    
    [Parameter(Mandatory=$false)]
    [string]$KeyVaultSubscriptionId = "",
    
    [Parameter(Mandatory=$false)]
    [int]$ExpirationThresholdDays = 30,
    
    [switch]$DryRun,
    [switch]$ForceRestart,
    [switch]$AllNamespaces
)

$ErrorActionPreference = "Stop"

# Validate parameters
if (-not $AllNamespaces -and [string]::IsNullOrWhiteSpace($Namespace)) {
    Write-Host "ERROR: Either -Namespace or -AllNamespaces must be specified" -ForegroundColor Red
    exit 1
}

if ($AllNamespaces -and -not [string]::IsNullOrWhiteSpace($Namespace)) {
    Write-Host "ERROR: Cannot specify both -Namespace and -AllNamespaces" -ForegroundColor Red
    exit 1
}

# Function to get all user namespaces (excluding system namespaces)
function Get-UserNamespaces {
    Write-Host "Discovering all namespaces in cluster..." -ForegroundColor Cyan
    
    $namespacesJson = kubectl get namespaces -o json 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to get namespaces from cluster" -ForegroundColor Red
        Write-Host $namespacesJson -ForegroundColor Red
        exit 1
    }
    
    $namespaces = ($namespacesJson | ConvertFrom-Json).items
    
    # System namespaces to exclude
    $systemNamespaces = @(
        'default',
        'kube-system',
        'kube-public',
        'kube-node-lease',
        'cattle-fleet-system',
        'calico-system',
        'calico-apiserver',
        'tigera-operator',
        'aks-command',
        'gatekeeper-system',
        'azure-arc',
        'cluster-baseline-settings',
		'monitoring-dev-inc-xtr',
		'monitoring-inc-dev-xtr',
		'monitoring-inc-rnd-xtr',
		'monitoring-we-prod-xtr',
        'monitoring-eus-dev-xtr',
		'version-monitoring',
        'monitoring-we-uat-xtr',
        'monitoring-we-dev-xtr',
        'monitoring-eus-uat-xtr',
        'helm-monitoring',
        'blackbox-monitoring',
		'wiz'
    )
    
    # Filter out system namespaces
    $userNamespaces = $namespaces | Where-Object {
        $ns = $_.metadata.name
        $isSystem = $false
        
        # Check exact matches
        if ($systemNamespaces -contains $ns) {
            $isSystem = $true
        }
        
        # Check prefixes
        if ($ns -match '^kube-' -or $ns -match '^aks-' -or $ns -match '^azure-') {
            $isSystem = $true
        }
        
        -not $isSystem
    } | ForEach-Object { $_.metadata.name }
    
    return $userNamespaces
}

# Determine which namespaces to process
if ($AllNamespaces) {
    $namespacesToProcess = Get-UserNamespaces
    Write-Host "Found $($namespacesToProcess.Count) user namespace(s) to scan" -ForegroundColor Green
    Write-Host ""
} else {
    $namespacesToProcess = @($Namespace)
}

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Automatic Certificate Renewal" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
if ($AllNamespaces) {
    Write-Host "Mode:                   ALL NAMESPACES ($($namespacesToProcess.Count) user namespaces)" -ForegroundColor White
} else {
    Write-Host "Mode:                   SINGLE NAMESPACE" -ForegroundColor White
    Write-Host "Namespace:              $Namespace" -ForegroundColor White
}
Write-Host "Key Vault:              $KeyVaultName" -ForegroundColor White
Write-Host "Certificate Secret:     $CertificateSecretName" -ForegroundColor White
Write-Host "Key Secret:             $KeySecretName" -ForegroundColor White
Write-Host "Expiration Threshold:   $ExpirationThresholdDays days" -ForegroundColor White
Write-Host "Dry Run:                $DryRun" -ForegroundColor White
Write-Host "Force Restart:          $ForceRestart" -ForegroundColor White
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Initialize global counters for all namespaces
$global:allSecretsToRenew = @()
$global:totalTlsSecretsFound = 0

# Process each namespace
foreach ($currentNamespace in $namespacesToProcess) {
    if ($AllNamespaces) {
        Write-Host "============================================================" -ForegroundColor DarkCyan
        Write-Host "Processing Namespace: $currentNamespace" -ForegroundColor DarkCyan
        Write-Host "============================================================" -ForegroundColor DarkCyan
        Write-Host ""
    }

# Step 1: Find all TLS secrets in the namespace
Write-Host "Step 1: Discovering TLS secrets in namespace '$currentNamespace'..." -ForegroundColor Yellow
Write-Host ""

$secretsJson = kubectl get secrets -n $currentNamespace -o json 2>&1
if ($LASTEXITCODE -ne 0) {
    if ($AllNamespaces) {
        Write-Host "Warning: Failed to get secrets from namespace '$currentNamespace', skipping..." -ForegroundColor Yellow
        Write-Host ""
        continue
    } else {
        Write-Host "Warning: Failed to get secrets from namespace '$currentNamespace'" -ForegroundColor Yellow
        Write-Host $secretsJson -ForegroundColor Yellow
        Write-Host ""
        Write-Host "##vso[task.setvariable variable=renewalMode;isOutput=true]NoCertsNeeded"
        Write-Host "##vso[task.setvariable variable=secretsToRenew;isOutput=true]0"
        Write-Host "##vso[task.setvariable variable=secretsRenewed;isOutput=true]0"
        Write-Host "##vso[task.setvariable variable=namespacesAffected;isOutput=true]"
        Write-Host "##vso[task.setvariable variable=secretDetails;isOutput=true]"
        exit 0
}
}

$secrets = $secretsJson | ConvertFrom-Json
$tlsSecrets = $secrets.items | Where-Object { $_.type -eq "kubernetes.io/tls" }

$global:totalTlsSecretsFound += $tlsSecrets.Count

if ($tlsSecrets.Count -eq 0) {
    Write-Host "No TLS secrets found in namespace '$currentNamespace'" -ForegroundColor Yellow
    Write-Host ""
    if (-not $AllNamespaces) {
        Write-Host "##vso[task.setvariable variable=renewalMode;isOutput=true]NoCertsNeeded"
        Write-Host "##vso[task.setvariable variable=secretsToRenew;isOutput=true]0"
        Write-Host "##vso[task.setvariable variable=secretsRenewed;isOutput=true]0"
        Write-Host "##vso[task.setvariable variable=namespacesAffected;isOutput=true]"
        Write-Host "##vso[task.setvariable variable=secretDetails;isOutput=true]"
        exit 0
    }
    continue
}

Write-Host "Found $($tlsSecrets.Count) TLS secret(s):" -ForegroundColor Green
foreach ($secret in $tlsSecrets) {
    Write-Host "  - $($secret.metadata.name)" -ForegroundColor White
}
Write-Host ""

# Step 2: Check expiration for each TLS secret
Write-Host "Step 2: Checking certificate expiration..." -ForegroundColor Yellow
Write-Host ""

$secretsToRenew = @()

foreach ($secret in $tlsSecrets) {
    $secretName = $secret.metadata.name
    Write-Host "Checking secret: $secretName" -ForegroundColor Cyan
    
    # Get certificate data
    $certData = $secret.data.'tls.crt'
    if (-not $certData) {
        Write-Host "  WARNING: No tls.crt found in secret, skipping" -ForegroundColor Yellow
        Write-Host ""
        continue
    }
    
    # Decode certificate and check expiration
    try {
        # Decode base64 to get PEM text
        $certBytes = [System.Convert]::FromBase64String($certData)
        $pemText = [System.Text.Encoding]::UTF8.GetString($certBytes)
        
        # Save to temp file for certificate parsing
        $tempCertFile = [System.IO.Path]::GetTempFileName()
        $pemText | Out-File -FilePath $tempCertFile -Encoding ASCII -NoNewline
        
        # Load certificate using .NET X509Certificate2
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tempCertFile)
        
        $expirationDate = $cert.NotAfter
        $daysUntilExpiration = ($expirationDate - (Get-Date)).Days
        
        Write-Host "  Subject:     $($cert.Subject)" -ForegroundColor White
        Write-Host "  Issuer:      $($cert.Issuer)" -ForegroundColor White
        Write-Host "  Expires:     $expirationDate" -ForegroundColor White
        Write-Host "  Days left:   $daysUntilExpiration" -ForegroundColor $(if ($daysUntilExpiration -lt $ExpirationThresholdDays) { 'Yellow' } else { 'Green' })
        
        if ($daysUntilExpiration -lt $ExpirationThresholdDays) {
            Write-Host "  NEEDS RENEWAL (< $ExpirationThresholdDays days)" -ForegroundColor Yellow
            $secretsToRenew += @{
                Name = $secretName
                Namespace = $currentNamespace
                CurrentExpiration = $expirationDate
                DaysLeft = $daysUntilExpiration
            }
        } else {
            Write-Host "  [OK] Certificate still valid" -ForegroundColor Green
        }
        
        # Cleanup temp file
        Remove-Item -Path $tempCertFile -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Host "  WARNING: Failed to parse certificate: $($_.Exception.Message)" -ForegroundColor Red
        # Cleanup temp file on error
        if ($tempCertFile -and (Test-Path $tempCertFile)) {
            Remove-Item -Path $tempCertFile -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Host ""
}

# Add secrets from this namespace to global list
$global:allSecretsToRenew += $secretsToRenew

if ($secretsToRenew.Count -gt 0) {
    Write-Host "Found $($secretsToRenew.Count) certificate(s) requiring renewal in this namespace" -ForegroundColor Yellow
    foreach ($secretInfo in $secretsToRenew) {
        Write-Host "  - $($secretInfo.Name) (expires in $($secretInfo.DaysLeft) days)" -ForegroundColor White
    }
} else {
    Write-Host "No certificates need renewal in this namespace" -ForegroundColor Green
}
Write-Host ""

} # End of foreach namespace loop

# Final processing after scanning all namespaces
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Scan Complete" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($global:allSecretsToRenew.Count -eq 0) {
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "No certificates need renewal" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    if ($AllNamespaces) {
        Write-Host "All certificates in all scanned namespaces are valid for more than $ExpirationThresholdDays days." -ForegroundColor Green
    } else {
        Write-Host "All certificates in namespace '$Namespace' are valid for more than $ExpirationThresholdDays days." -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "##vso[task.setvariable variable=renewalMode;isOutput=true]NoCertsNeeded"
    Write-Host "##vso[task.setvariable variable=secretsToRenew;isOutput=true]0"
    Write-Host "##vso[task.setvariable variable=secretsRenewed;isOutput=true]0"
    Write-Host "##vso[task.setvariable variable=namespacesAffected;isOutput=true]"
    Write-Host "##vso[task.setvariable variable=secretDetails;isOutput=true]"
    exit 0
}

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "Certificates requiring renewal: $($global:allSecretsToRenew.Count)" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

# Group by namespace for display
$secretsByNamespace = $global:allSecretsToRenew | Group-Object -Property Namespace
foreach ($nsGroup in $secretsByNamespace) {
    if ($AllNamespaces) {
        Write-Host "Namespace: $($nsGroup.Name)" -ForegroundColor Cyan
    }
    foreach ($secretInfo in $nsGroup.Group) {
        if ($AllNamespaces) {
            Write-Host "  - $($secretInfo.Name) (expires in $($secretInfo.DaysLeft) days)" -ForegroundColor White
        } else {
            Write-Host "  - $($secretInfo.Name) (expires in $($secretInfo.DaysLeft) days)" -ForegroundColor White
        }
    }
    if ($AllNamespaces) {
        Write-Host ""
    }
}
Write-Host ""

if ($DryRun) {
    # Build detailed summary for dry run
    $namespacesAffected = ($global:allSecretsToRenew | Select-Object -ExpandProperty Namespace -Unique) -join ","
    $secretDetails = $global:allSecretsToRenew | ForEach-Object { "$($_.Namespace)/$($_.Name)" }
    $secretDetailsList = $secretDetails -join ","
    
    Write-Host "[DRY RUN] Would renew the above certificates" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "##vso[task.setvariable variable=renewalMode;isOutput=true]DryRun"
    Write-Host "##vso[task.setvariable variable=secretsToRenew;isOutput=true]$($global:allSecretsToRenew.Count)"
    Write-Host "##vso[task.setvariable variable=secretsRenewed;isOutput=true]0"
    Write-Host "##vso[task.setvariable variable=namespacesAffected;isOutput=true]$namespacesAffected"
    Write-Host "##vso[task.setvariable variable=secretDetails;isOutput=true]$secretDetailsList"
    exit 0
}

# Step 4: Download certificate from Key Vault

Write-Host "Step 3: Downloading certificate and key from Key Vault secrets..." -ForegroundColor Yellow
Write-Host ""

# Switch to Key Vault subscription if specified
if ($KeyVaultSubscriptionId) {
    Write-Host "Switching to Key Vault subscription: $KeyVaultSubscriptionId" -ForegroundColor Cyan
    az account set --subscription $KeyVaultSubscriptionId 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to switch to subscription $KeyVaultSubscriptionId" -ForegroundColor Red
        exit 1
    }
}

# Download certificate PEM from secret
Write-Host "Downloading certificate PEM from secret '$CertificateSecretName' in Key Vault '$KeyVaultName'..." -ForegroundColor Cyan
$certificatePem = az keyvault secret show --vault-name $KeyVaultName --name $CertificateSecretName --query "value" --output tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($certificatePem)) {
    Write-Host "Error: Failed to download certificate PEM from Key Vault" -ForegroundColor Red
    exit 1
}

# Download key PEM from secret
Write-Host "Downloading private key PEM from secret '$KeySecretName' in Key Vault '$KeyVaultName'..." -ForegroundColor Cyan
$keyPem = az keyvault secret show --vault-name $KeyVaultName --name $KeySecretName --query "value" --output tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($keyPem)) {
    Write-Host "Error: Failed to download private key PEM from Key Vault" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Certificate and key downloaded successfully" -ForegroundColor Green
Write-Host ""

# Step 6: Update each secret that needs renewal
Write-Host "Step 5: Updating Kubernetes secrets..." -ForegroundColor Yellow
Write-Host ""

$updatedCount = 0
$failedCount = 0

foreach ($secretInfo in $global:allSecretsToRenew) {
    $secretName = $secretInfo.Name
    $secretNamespace = $secretInfo.Namespace
    
    if ($AllNamespaces) {
        Write-Host "Updating secret: $secretName in namespace: $secretNamespace" -ForegroundColor Cyan
    } else {
        Write-Host "Updating secret: $secretName" -ForegroundColor Cyan
    }
    
    # Create temporary files for kubectl
    $certFile = [System.IO.Path]::GetTempFileName()
    $keyFile = [System.IO.Path]::GetTempFileName()
    
    try {
        # Write PEM files
        [System.IO.File]::WriteAllText($certFile, $certPem)
        [System.IO.File]::WriteAllText($keyFile, $keyPem)
        
        # Delete existing secret
        kubectl delete secret $secretName -n $secretNamespace 2>&1 | Out-Null
        
        # Create new secret with updated certificate
        $createResult = kubectl create secret tls $secretName `
            --cert=$certFile `
            --key=$keyFile `
            -n $secretNamespace 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Secret updated successfully" -ForegroundColor Green
            $updatedCount++
        } else {
            Write-Host "  ERROR: Failed to update secret" -ForegroundColor Red
            Write-Host "  Error: $createResult" -ForegroundColor Red
            $failedCount++
        }
        
    } catch {
        Write-Host "  ERROR: Error updating secret: $($_.Exception.Message)" -ForegroundColor Red
        $failedCount++
    } finally {
        # Cleanup temp files
        Remove-Item $certFile -Force -ErrorAction SilentlyContinue
        Remove-Item $keyFile -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host ""
}

# Step 7: Restart pods if requested
if ($ForceRestart -and $updatedCount -gt 0) {
    Write-Host "Step 6: Restarting pods to apply new certificates..." -ForegroundColor Yellow
    Write-Host ""
    
    # Get unique namespaces that had secrets updated
    $namespacesWithUpdates = $global:allSecretsToRenew | Select-Object -ExpandProperty Namespace -Unique
    
    foreach ($ns in $namespacesWithUpdates) {
        if ($AllNamespaces) {
            Write-Host "Restarting deployments in namespace: $ns" -ForegroundColor Cyan
        }
        
        $deployments = kubectl get deployments -n $ns -o json 2>&1 | ConvertFrom-Json
        
        if ($deployments.items) {
            foreach ($deployment in $deployments.items) {
                $depName = $deployment.metadata.name
                if ($AllNamespaces) {
                    Write-Host "  Restarting deployment: $depName" -ForegroundColor White
                } else {
                    Write-Host "Restarting deployment: $depName" -ForegroundColor Cyan
                }
                
                kubectl rollout restart deployment/$depName -n $ns 2>&1 | Out-Null
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "    [OK] Deployment restarted" -ForegroundColor Green
                } else {
                    Write-Host "    WARNING: Failed to restart deployment" -ForegroundColor Yellow
                }
            }
        }
    }
    
    Write-Host ""
}

# Final summary
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Certificate Renewal Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
if ($AllNamespaces) {
    Write-Host "Mode:                ALL NAMESPACES" -ForegroundColor White
    Write-Host "Namespaces scanned:  $($namespacesToProcess.Count)" -ForegroundColor White
    Write-Host "Total TLS secrets:   $($global:totalTlsSecretsFound)" -ForegroundColor White
} else {
    Write-Host "Namespace:           $Namespace" -ForegroundColor White
    Write-Host "TLS secrets found:   $($global:totalTlsSecretsFound)" -ForegroundColor White
}
Write-Host "Secrets needing renewal: $($global:allSecretsToRenew.Count)" -ForegroundColor White
Write-Host "Secrets renewed:     $updatedCount" -ForegroundColor $(if ($updatedCount -gt 0) { 'Green' } else { 'White' })
Write-Host "Secrets failed:      $failedCount" -ForegroundColor $(if ($failedCount -gt 0) { 'Red' } else { 'White' })
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($failedCount -gt 0) {
    Write-Host "WARNING: Some certificates failed to renew. Check logs above for details." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Build detailed summary for output variables
$namespacesAffected = ($global:allSecretsToRenew | Select-Object -ExpandProperty Namespace -Unique) -join ","
$secretDetails = $global:allSecretsToRenew | ForEach-Object { "$($_.Namespace)/$($_.Name)" }
$secretDetailsList = $secretDetails -join ","

Write-Host "##vso[task.setvariable variable=renewalMode;isOutput=true]Renewed"
Write-Host "##vso[task.setvariable variable=secretsToRenew;isOutput=true]$($global:allSecretsToRenew.Count)"
Write-Host "##vso[task.setvariable variable=secretsRenewed;isOutput=true]$updatedCount"
Write-Host "##vso[task.setvariable variable=namespacesAffected;isOutput=true]$namespacesAffected"
Write-Host "##vso[task.setvariable variable=secretDetails;isOutput=true]$secretDetailsList"

if ($updatedCount -gt 0) {
    Write-Host "SUCCESS: Certificate renewal completed successfully!" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "INFO: No certificates were renewed." -ForegroundColor Cyan
    Write-Host ""
}

exit 0
