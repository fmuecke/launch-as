# Manual smoke test: verifies the broker is installed, then launches cmd.exe as LaunchAsUser.
# Run after .\build.ps1 and .\Setup-LaunchAs.ps1.

function Test-BrokerServiceInstalled {
    $serviceControl = Join-Path $env:SystemRoot 'System32\sc.exe'
    $query = @(& $serviceControl query launch-as-broker 2>&1)
    if ($LASTEXITCODE -eq 0) {
        return $true
    }
    $queryText = $query | Out-String
    if ($queryText -match '(?i)failed\s+1060') {
        return $false
    }
    if ($queryText -match '(?i)failed\s+5') {
        Write-Verbose 'The service DACL denies query status; continuing so the launcher can use delegated SERVICE_START.'
        return $true
    }
    throw "Could not query launch-as-broker: $queryText"
}

if (-not (Test-BrokerServiceInstalled)) {
    Write-Host 'launch-as-broker is not installed.'
    Write-Host 'Build the project, then run .\Setup-LaunchAs.ps1 to install and enroll it.'
    exit 1
}

.\out\build\Release\launch-as.exe `
    --user LaunchAsUser `
    --working-directory C:\dev\ `
    -- C:\Windows\System32\cmd.exe /d /k
