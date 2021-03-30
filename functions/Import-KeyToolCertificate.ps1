function Import-KeyToolCertificate {
    <#
        .SYNOPSIS
            Imports a certificate into the specified KeyStore using the Java KeyTool.
        .PARAMETER Alias
            Alias to use when importing the certificate into the KeyStore.
        .PARAMETER File
            Path to the certificate file to import.
        .PARAMETER KeyStore
            Path to the KeyStore file, to import the certificate for.
        .PARAMETER StorePass
            Password to use for the KeyStore file.
        .PARAMETER StoreType
            Type of store for the KeyStore.
    #>

    param(
        [Parameter(Mandatory = $false)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [string]
        $Alias,

        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path $_ })]
        [string]
        $File,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]
        $KeyStore,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('KeyStorePass')]
        [string]
        $StorePass,

        [Parameter(Mandatory = $false)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('KeyStoreType')]
        [string]
        $StoreType
    )

    $result = Invoke-KeyTool `
        -Arguments @(
            '-noprompt',
            '-v'
        ) `
        -CommandName 'importcert' `
        -ParamArguments $PSBoundParameters

    switch -Wildcard ($result) {
        'Certificate was added to keystore*' {
            return Get-KeyStoreCertificate `
                -Alias $Alias `
                -KeyStore $KeyStore `
                -StorePass $StorePass `
                -StoreType $StoreType
        }
        default {
            throw $result
        }
    }
}