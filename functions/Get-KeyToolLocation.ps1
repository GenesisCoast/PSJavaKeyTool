function Get-KeyToolLocation {
    <#
        .SYNOPSIS
            Gets the location of the KeyTool on the client machine, will use the lastest version.
    #>

    $found = $false

    $packages = Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' `
        | Where-Object { $_.DisplayName -like "*Java*" } `
        | ForEach-Object { $_.DisplayVersion = [version]::Parse($_.DisplayVersion) } `
        | Sort-Object -Descending -Property 'DisplayVersion'

    foreach ($package in $packages) {
        $keytool = Get-ChildItem `
            -ErrorAction 'SilentlyContinue' `
            -Filter 'keytool.exe' `
            -Path $package.InstallLocation `
            -Recurse `
            | Select-Object -First 1

        if ($null -ne $keytool) {
            $found = $true
            break
        }
    }

    if ($found -eq $true) {
        return $keytool.FullName
    }
    else {
        throw (
            'Could not find a version of Java that contains keytool.exe, ' +
            'please install a version of the development kit.'
        )
    }
}