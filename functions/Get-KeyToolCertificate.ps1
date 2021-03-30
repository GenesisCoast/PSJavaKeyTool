function Get-KeyToolCertificate {
    <#
        .SYNOPSIS
            Gets the details of the certificates imported into the KeyStore.
        .DESCRIPTION
            Lists the details of the certificates currently imported into the
            Java KeyStore. If an Alias is suplied then the function will retrieve
            the details for the specified certificate only.
        .PARAMETER Alias
            The Alias of the certificate to get from the KeyStore.
        .PARAMETER KeyStore
            Name of the KeyStore to interrogate for information.
        .PARAMETER StorePass
            Password for the KeyStore.
        .PARAMETER StoreType
            Type of KeyStore.
        .EXAMPLE
            Get-KeyStoreCertificate `
                -Alias 'mykey' `
                -KeyStore 'tomcat.keystore' `
                -StorePass 'password1234'
    #>

    param(
        [Parameter(
            Mandatory = $false,
            Position  = 2
        )]
        [ValidateScript({ -not [string]::IsNullOrWhitepsace($_) })]
        [string]
        $Alias,

        [Parameter(
            Mandatory = $true,
            Position  = 0
        )]
        [ValidateScript({ Test-Path $_ })]
        [string]
        $KeyStore,

        [Parameter(
            Mandatory = $true,
            Position  = 1
        )]
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
        -CommandName 'list' `
        -Parameters $PSBoundParameters

    switch -Wildcard ($result) {
        '*Your keystore contains*' {
            return ConvertFrom-KeyToolCertificateDetails $result
        }
        '*Certificate fingerprint*' {
            return ConvertFrom-KeyToolCertificateDetails $result
        }
        default {
            throw $result
        }
    }
}