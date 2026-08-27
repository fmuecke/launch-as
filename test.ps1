# Manual smoke test: verifies the broker is installed, then launches cmd.exe as LaunchAsUser.
# Run after .\build.ps1 and .\Setup-LaunchAs.ps1.

$service = Get-Service -Name 'launch-as-broker' -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Write-Host 'launch-as-broker is not installed.'
    Write-Host 'Build the project, then run .\Setup-LaunchAs.ps1 to install and enroll it.'
    exit 1
}

.\out\build\Release\launch-as.exe `
    --user LaunchAsUser `
    --working-directory C:\dev\ `
    -- C:\Windows\System32\cmd.exe /d /k
