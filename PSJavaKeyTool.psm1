#requires -Version 5.0
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$members = @()

# Import all the functions.
$members += Get-ChildItem `
    -ErrorAction SilentlyContinue `
    -Exclude @(
        '*.tests.ps1',
        '*profile.ps1'
    ) `
    -Path "$PSScriptRoot\functions\*.ps1"

# Import any classes.
$members += Get-ChildItem `
    -ErrorAction SilentlyContinue `
    -Path "$PSScriptRoot\classes\*.ps1"

# Run the dot `.` sourcing of all the individual files.
$members.foreach({
    try {
        Write-Verbose "Dot sourcing [$($_.FullName)]"
        . $_.FullName
    }
    catch {
        throw "Unable to dot source [$($_.FullName)]"
    }
})

# Export module members.
Export-ModuleMember -Function * -Alias *