function Remove-KeyToolCertificate {
    <#
        .SYNOPSIS
            Removes the specified certificate from the KeyStore, using the Java KeyTool.
        .PARAMETER Alias
            Alias of the certificate to remove.
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
        -CommandName 'delete' `
        -ParamArguments $PSBoundParameters

    switch -Wildcard ($result) {
        '*Storing*' {
            break
        }
        default {
            throw $result
        }
    }
}