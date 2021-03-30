function Set-KeyToolCertificateAlias {
    <#
        .SYNOPSIS
            Renames an existing certificate alias.
        .PARAMETER Alias
            The certificate alias to rename.
        .PARAMETER DestAlias
            The new alias for the certificate.
        .PARAMETER KeyStore
            Path to the KeyStore file, to remove the certificate from.
        .PARAMETER StorePass
            Password for the KeyStore.
        .PARAMETER StoreType
            Type of KeyStore.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [string]
        $Alias,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('DestinationAlias')]
        [string]
        $DestAlias,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]
        $KeyStore,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [string]
        $StorePass,

        [Parameter(Mandatory = $false)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [string]
        $StoreType
    )

    $result = Invoke-KeyTool `
        -Arguments @(
            '-v'
        ) `
        -CommandName 'changealias' `
        -ParamArguments $PSBoundParameters

    switch -Wildcard ($result) {
        '*Storing*' {
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