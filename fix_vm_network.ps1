# Fix VMware VM network settings to NAT (VMnet8)
# VMs must be POWERED OFF before modifying .vmx files

$vmsToFix = @(
    "D:\Dissertation\Windows Server 2012.vmx",
    "D:\PHD-RESEARCH\windows 10\Windows 10 x64.vmx"
)

foreach ($vmx in $vmsToFix) {
    if (Test-Path $vmx) {
        $name = Split-Path $vmx -Leaf
        Write-Host "Fixing $name ..."
        
        $content = Get-Content $vmx -Raw
        
        # Replace connectionType
        if ($content -match 'ethernet0\.connectionType\s*=\s*"[^"]*"') {
            $content = $content -replace 'ethernet0\.connectionType\s*=\s*"[^"]*"', 'ethernet0.connectionType = "nat"'
        } else {
            $content += "`nethernet0.connectionType = `"nat`""
        }
        
        # Remove custom vnet reference (NAT uses VMnet8 automatically)
        $content = $content -replace 'ethernet0\.vnet\s*=\s*"VMnet1"', 'ethernet0.vnet = "VMnet8"'
        
        Set-Content $vmx -Value $content -NoNewline
        Write-Host "  -> Set to NAT (VMnet8)"
    } else {
        Write-Host "SKIP: $vmx not found"
    }
}

# Fix Windows 11 PHD (missing ethernet config)
$w11 = "D:\PHD-RESEARCH\Windows 11\Windows 11 x64.vmx"
if (Test-Path $w11) {
    $content = Get-Content $w11 -Raw
    if ($content -notmatch 'ethernet0\.connectionType') {
        $content += "`nethernet0.connectionType = `"nat`""
        $content += "`nethernet0.vnet = `"VMnet8`""
        Set-Content $w11 -Value $content -NoNewline
        Write-Host "Fixed Windows 11 PHD -> Added NAT config"
    }
}

Write-Host "`n=== All VMs now configured for NAT (VMnet8 / 192.168.195.x) ==="
