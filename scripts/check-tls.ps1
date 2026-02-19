param(
    [Parameter(Position=0)]
    [string]$Namespace = "",
    
    [switch]$AllNamespaces
)

$ErrorActionPreference = "Stop"

# Validate parameters
if (-not $AllNamespaces -and [string]::IsNullOrWhiteSpace($Namespace)) {
    Write-Host "ERROR: Either -Namespace or -AllNamespaces must be specified" -ForegroundColor Red
    Write-Host "Usage: .\check-tls.ps1 -Namespace <namespace>" -ForegroundColor Yellow
    Write-Host "   or: .\check-tls.ps1 -AllNamespaces" -ForegroundColor Yellow
    exit 1
}

if ($AllNamespaces -and -not [string]::IsNullOrWhiteSpace($Namespace)) {
    Write-Host "ERROR: Cannot specify both -Namespace and -AllNamespaces" -ForegroundColor Red
    exit 1
}

# Colors
function Write-ColorOutput($ForegroundColor, $Message) {
    Write-Host $Message -ForegroundColor $ForegroundColor
}

# Function to get all user namespaces (excluding system namespaces)
function Get-UserNamespaces {
    $namespacesJson = kubectl get namespaces -o json 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to get namespaces from cluster" -ForegroundColor Red
        exit 1
    }
    
    $namespaces = ($namespacesJson | ConvertFrom-Json).items
    
    # System namespaces to exclude
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
        'monitoring-we-uat-xtr',
		'version-monitoring',
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
        
        if ($systemNamespaces -contains $ns) {
            $isSystem = $true
        }
        
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
    Write-ColorOutput "Blue" "TLS Certificate Check for ALL user namespaces ($($namespacesToProcess.Count) namespaces)"
} else {
    $namespacesToProcess = @($Namespace)
    Write-ColorOutput "Blue" "TLS Certificate Check for namespace: $Namespace"
}
Write-Host ""

# Process each namespace
foreach ($currentNamespace in $namespacesToProcess) {
    if ($AllNamespaces) {
        Write-Host ""
        Write-ColorOutput "Cyan" "=========================================================================="
        Write-ColorOutput "Cyan" "Namespace: $currentNamespace"
        Write-ColorOutput "Cyan" "=========================================================================="
        Write-Host ""
    }

# Check if namespace exists
try {
    kubectl get namespace $currentNamespace 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        if ($AllNamespaces) {
            Write-ColorOutput "Yellow" "Namespace '$currentNamespace' not found, skipping..."
            continue
        } else {
            Write-ColorOutput "Yellow" "Namespace '$currentNamespace' not found"
            Write-Host ""
            Write-Host "No certificate verification needed." -ForegroundColor Cyan
            exit 0
        }
    }
} catch {
    if ($AllNamespaces) {
        Write-ColorOutput "Yellow" "Namespace '$currentNamespace' not accessible, skipping..."
        continue
    } else {
        Write-ColorOutput "Yellow" "Namespace '$currentNamespace' not accessible"
        Write-Host ""
        Write-Host "No certificate verification needed." -ForegroundColor Cyan
        exit 0
    }
}

# 1. List all TLS secrets
Write-ColorOutput "Cyan" "=========================================="
Write-ColorOutput "Blue" "TLS Secrets:"
Write-ColorOutput "Cyan" "=========================================="
kubectl get secrets -n $currentNamespace --field-selector type=kubernetes.io/tls -o custom-columns=NAME:.metadata.name,AGE:.metadata.creationTimestamp
Write-Host ""

# 2. Check cert-manager Certificates
Write-ColorOutput "Cyan" "=========================================="
Write-ColorOutput "Blue" "Certificates (cert-manager):"
Write-ColorOutput "Cyan" "=========================================="
try {
    kubectl get certificates -n $currentNamespace 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        kubectl get certificates -n $currentNamespace -o wide
    } else {
        Write-ColorOutput "Yellow" "No Certificate resources found (cert-manager may not be installed)"
    }
} catch {
    Write-ColorOutput "Yellow" "No Certificate resources found (cert-manager may not be installed)"
}
Write-Host ""

# 3. Check Ingress TLS configuration
Write-ColorOutput "Cyan" "=========================================="
Write-ColorOutput "Blue" "Ingress TLS Configuration:"
Write-ColorOutput "Cyan" "=========================================="
try {
    $ingressOutput = kubectl get ingress -n $currentNamespace 2>&1
    if ($LASTEXITCODE -eq 0) {
        kubectl get ingress -n $currentNamespace
        Write-Host ""
        Write-ColorOutput "Blue" "Ingress TLS Details:"
        
        # Get ingress list as JSON and parse
        $ingressJson = kubectl get ingress -n $currentNamespace -o json | ConvertFrom-Json
        foreach ($ingress in $ingressJson.items) {
            Write-Host $ingress.metadata.name
            if ($ingress.spec.tls) {
                foreach ($tls in $ingress.spec.tls) {
                    Write-Host "  TLS Host: $($tls.hosts -join ', ')"
                    Write-Host "  Secret: $($tls.secretName)"
                }
            } else {
                Write-Host "  No TLS configuration"
            }
            Write-Host ""
        }
    } else {
        Write-ColorOutput "Yellow" "No Ingress found"
    }
} catch {
    Write-ColorOutput "Yellow" "No Ingress found"
}
Write-Host ""

# 4. Get the first TLS secret and show certificate details
$SECRET = kubectl get secrets -n $currentNamespace --field-selector type=kubernetes.io/tls -o jsonpath='{.items[0].metadata.name}' 2>$null

if ($SECRET) {
    Write-ColorOutput "Cyan" "=========================================="
    Write-ColorOutput "Blue" "Certificate Details: $SECRET"
    Write-ColorOutput "Cyan" "=========================================="
    
    $CERT_DATA_BASE64 = kubectl get secret $SECRET -n $currentNamespace -o jsonpath='{.data.tls\.crt}' 2>$null
    
    if ($CERT_DATA_BASE64) {
        try {
            # Decode base64
            $CERT_DATA = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($CERT_DATA_BASE64))
            
            # Save to temp file for certificate parsing
            $tempCertFile = [System.IO.Path]::GetTempFileName()
            $CERT_DATA | Out-File -FilePath $tempCertFile -Encoding ASCII -NoNewline
            
            # Load certificate using .NET X509Certificate2
            $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tempCertFile)
            
            Write-Host ""
            Write-ColorOutput "Blue" "Certificate Validity:"
            Write-Host "  Not Before: $($x509.NotBefore)"
            Write-Host "  Not After:  $($x509.NotAfter)"
            
            Write-Host ""
            Write-ColorOutput "Blue" "Subject and Issuer:"
            Write-Host "  Subject: $($x509.Subject)"
            Write-Host "  Issuer:  $($x509.Issuer)"
            
            Write-Host ""
            Write-ColorOutput "Blue" "Certificate Information:"
            Write-Host "  Serial Number: $($x509.SerialNumber)"
            Write-Host "  Thumbprint:    $($x509.Thumbprint)"
            Write-Host "  Version:       $($x509.Version)"
            
            # Extract Subject Alternative Names
            Write-Host ""
            Write-ColorOutput "Blue" "Subject Alternative Names (SANs):"
            $sanExtension = $x509.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            if ($sanExtension) {
                $sans = $sanExtension.Format($false) -split ', '
                foreach ($san in $sans) {
                    Write-Host "  $san"
                }
            } else {
                Write-Host "  No SANs found"
            }
            
            # Calculate days until expiration
            $daysLeft = ($x509.NotAfter - (Get-Date)).Days
            
            Write-Host ""
            if ($daysLeft -lt 0) {
                Write-ColorOutput "Red" "EXPIRED: Certificate expired $([Math]::Abs($daysLeft)) days ago!"
            } elseif ($daysLeft -lt 30) {
                Write-ColorOutput "Red" "WARNING: Certificate expires in $daysLeft days!"
            } elseif ($daysLeft -lt 60) {
                Write-ColorOutput "Yellow" "WARNING: Certificate expires in $daysLeft days"
            } else {
                Write-ColorOutput "Green" "OK: Certificate valid for $daysLeft days"
            }
            
            # Cleanup
            Remove-Item -Path $tempCertFile -Force -ErrorAction SilentlyContinue
            
        } catch {
            Write-ColorOutput "Red" "Error parsing certificate: $($_.Exception.Message)"
        }
    } else {
        Write-ColorOutput "Red" "Could not decode certificate data"
    }
} else {
    Write-ColorOutput "Yellow" "No TLS secrets found in namespace $currentNamespace"
}

} # End of foreach namespace loop

if ($AllNamespaces) {
    Write-Host ""
    Write-ColorOutput "Green" "=========================================================================="
    Write-ColorOutput "Green" "Scan complete for all user namespaces"
    Write-ColorOutput "Green" "=========================================================================="
}