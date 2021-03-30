function Import-KeyToolStore {
    <#
        .SYNOPSIS
            Imports another KeyStore into the destination KeyStore. Can be used to
            import PFX certificates.
        .PARAMETER DestAlias
            Alias of the destination KeyStore.
        .PARAMETER DestKeyStore
            Path to the destination KeyStore file. This is where the source KeyStore
            will be imported to.
        .PARAMETER DestStorePass
            Password for the destination KeyStore file.
        .PARAMETER DestStoreType
            Type of the destination KeyStore.
        .PARAMETER SrcAlias
            Alias for the source KeyStore.
        .PARAMETER SrcKeyStore
            Path to the source KeyStore file. This is what will be imported into the
            destination KeyStore.
        .PARAMETER SrcStorePass
            Password for the source KeyStore file.
        .PARAMETER SrcStoreType
            Type of the source KeyStore.
    #>

    param(
        [Parameter(Mandatory = $false)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('DestinationAlias')]
        [string]
        $DestAlias,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [Alias('DestinationKeyStore')]
        [string]
        $DestKeyStore,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('DestinationKeyStorePass')]
        [string]
        $DestStorePass,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('DestinationKeyStoreType')]
        [string]
        $DestStoreType,

        [Parameter(Mandatory = $false)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('SourceAlias')]
        [string]
        $SrcAlias,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [Alias('SourceKeyStore')]
        [string]
        $SrcKeyStore,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('SourceKeyStorePass')]
        [string]
        $SrcStorePass,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('SourceKeyStoreType')]
        [string]
        $SrcStoreType
    )

    if ($SrcStorePass -ne $DestStorePass) {
        Write-Warning (
            'The two store passes do not match, this may could compatibility issues.' +
            'depending on your use case.'
        )
    }

    $result = Invoke-KeyTool `
        -Arguments @(
            '-noprompt',
            '-v'
        ) `
        -CommandName 'importkeystore' `
        -ParamArguments $PSBoundParameters

    switch -Wildcard ($result) {
        'Certificate was added to keystore*' {
            return Get-KeyStoreCertificate `
                -Alias ((($result -isplit '{')[1] -isplit '}')[0]) `
                -KeyStore $DestKeyStore `
                -StorePass $DestStorePass `
                -StoreType $DestStoreType
        }
        default {
            throw $result
        }
    }
}