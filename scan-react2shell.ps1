<#
.SYNOPSIS
    Scans GitHub repositories for CVE-2025-55182 (React2Shell) vulnerability
.DESCRIPTION
    Checks for vulnerable versions of React 19.x and Next.js 15.x that use
    React Server Components (RSC) Flight protocol
.PARAMETER Path
    Root directory containing GitHub repositories (default: F:\GitHub\)
#>

param(
    [string]$Path = "F:\GitHub\"
)

$VulnerableRepos = @()
$SafeRepos = @()
$UnknownRepos = @()

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " CVE-2025-55182 (React2Shell) Scanner" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Scanning: $Path`n" -ForegroundColor Yellow

# Find all package.json files
$packageFiles = Get-ChildItem -Path $Path -Recurse -Filter "package.json" -ErrorAction SilentlyContinue | 
    Where-Object { $_.FullName -notmatch "node_modules" }

Write-Host "Found $($packageFiles.Count) package.json files to analyze...`n"

foreach ($file in $packageFiles) {
    $repoPath = $file.DirectoryName
    $repoName = Split-Path -Leaf (Split-Path -Parent $file.FullName)
    
    # Handle root-level package.json
    if ($file.Directory.FullName -eq (Resolve-Path $Path).Path.TrimEnd('\')) {
        $repoName = "[ROOT]"
    }
    
    try {
        $package = Get-Content $file.FullName -Raw | ConvertFrom-Json
        $deps = @{}
        
        # Combine dependencies and devDependencies
        if ($package.dependencies) {
            $package.dependencies.PSObject.Properties | ForEach-Object { $deps[$_.Name] = $_.Value }
        }
        if ($package.devDependencies) {
            $package.devDependencies.PSObject.Properties | ForEach-Object { $deps[$_.Name] = $_.Value }
        }
        
        $hasReact = $deps.ContainsKey("react")
        $hasNext = $deps.ContainsKey("next")
        $hasReactServer = $deps.ContainsKey("react-server-dom-webpack") -or $deps.ContainsKey("react-server-dom-esm")
        
        $reactVersion = $deps["react"]
        $nextVersion = $deps["next"]
        
        $isVulnerable = $false
        $vulnerabilityDetails = @()
        
        # Check React version
        if ($reactVersion -and $reactVersion -match "19\.") {
            # Check if it's a vulnerable version (19.0.0 - 19.2.0)
            if ($reactVersion -match "(\^|~)?19\.[0-2]\.") {
                $isVulnerable = $true
                $vulnerabilityDetails += "React $reactVersion (vulnerable: 19.0.0-19.2.0)"
            }
        }
        
        # Check Next.js version
        if ($nextVersion -and $nextVersion -match "15\.") {
            $isVulnerable = $true
            $vulnerabilityDetails += "Next.js $nextVersion (vulnerable: 15.x before patch)"
        }
        
        # Check for RSC packages
        if ($hasReactServer) {
            $vulnerabilityDetails += "Uses React Server Components packages"
        }
        
        # Check for "use server" directives in source files
        $serverDirectives = Get-ChildItem -Path $repoPath -Recurse -Include "*.js","*.jsx","*.ts","*.tsx" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch "node_modules" } |
            Select-String -Pattern '"use server"' -SimpleMatch -ErrorAction SilentlyContinue |
            Select-Object -First 1
        
        if ($serverDirectives) {
            $vulnerabilityDetails += "Contains 'use server' directives (Server Actions)"
        }
        
        # Categorize
        if ($isVulnerable) {
            $VulnerableRepos += [PSCustomObject]@{
                Name = $repoName
                Path = $file.FullName
                Details = $vulnerabilityDetails -join "; "
                ReactVersion = $reactVersion
                NextVersion = $nextVersion
            }
        }
        elseif ($hasReact -or $hasNext) {
            $SafeRepos += [PSCustomObject]@{
                Name = $repoName
                Path = $file.FullName
                ReactVersion = $reactVersion
                NextVersion = $nextVersion
            }
        }
    }
    catch {
        $UnknownRepos += [PSCustomObject]@{
            Name = $repoName
            Path = $file.FullName
            Error = $_.Exception.Message
        }
    }
}

# Output Results
Write-Host "`n========================================" -ForegroundColor Red
Write-Host " VULNERABLE REPOSITORIES ($($VulnerableRepos.Count))" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red

if ($VulnerableRepos.Count -gt 0) {
    foreach ($repo in $VulnerableRepos) {
        Write-Host "`n[!] $($repo.Name)" -ForegroundColor Red
        Write-Host "    Path: $($repo.Path)" -ForegroundColor Gray
        Write-Host "    Issue: $($repo.Details)" -ForegroundColor Yellow
    }
    
    Write-Host "`n----------------------------------------" -ForegroundColor Red
    Write-Host " REMEDIATION REQUIRED:" -ForegroundColor Red
    Write-Host "----------------------------------------" -ForegroundColor Red
    Write-Host " - React: Upgrade to 19.2.1 or later" -ForegroundColor White
    Write-Host " - Next.js: Upgrade to 15.2.4 or later" -ForegroundColor White
    Write-Host " - See: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components" -ForegroundColor Cyan
}
else {
    Write-Host "`nNo vulnerable repositories found!" -ForegroundColor Green
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " SAFE REPOSITORIES ($($SafeRepos.Count))" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

foreach ($repo in $SafeRepos) {
    $versions = @()
    if ($repo.ReactVersion) { $versions += "React: $($repo.ReactVersion)" }
    if ($repo.NextVersion) { $versions += "Next: $($repo.NextVersion)" }
    Write-Host "  [OK] $($repo.Name) - $($versions -join ', ')" -ForegroundColor Green
}

if ($UnknownRepos.Count -gt 0) {
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host " PARSE ERRORS ($($UnknownRepos.Count))" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    foreach ($repo in $UnknownRepos) {
        Write-Host "  [?] $($repo.Name): $($repo.Error)" -ForegroundColor Yellow
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Total package.json scanned: $($packageFiles.Count)"
Write-Host " Vulnerable: $($VulnerableRepos.Count)" -ForegroundColor $(if ($VulnerableRepos.Count -gt 0) { "Red" } else { "Green" })
Write-Host " Safe (React/Next but not vulnerable): $($SafeRepos.Count)" -ForegroundColor Green
Write-Host " Parse errors: $($UnknownRepos.Count)" -ForegroundColor Yellow

# Export results to CSV if vulnerable repos found
if ($VulnerableRepos.Count -gt 0) {
    $csvPath = Join-Path $Path "cve-2025-55182-scan-results.csv"
    $VulnerableRepos | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`nResults exported to: $csvPath" -ForegroundColor Cyan
}