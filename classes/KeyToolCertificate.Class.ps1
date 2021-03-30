class KeyToolCertificate {
    <#
        .SYNOPSIS
            Type for containing all the certificate details retrieved from the keystore.
        .DESCRIPTION
            The `KeyToolCertificate` type was created to provide an explicit type for all
            of the certificate details that are retrieved during the `Get-KeyToolCertificate`
            function. Eventually the type will be utilized in another functions in order to
            facilatate piping.
        .PARAMETER Alias​
        .PARAMETER CreationDate
        .PARAMETER EntryType
        .PARAMETER Issuer
        .PARAMETER Owner
        .PARAMETER SerialNumber
        .PARAMETER SHA1Thumbprint
        .PARAMETER SHA256Thumbprint
        .PARAMETER SignatureAlgorithmName
        .PARAMETER SubjectPublicKeyAlgorithm
        .PARAMETER ValidFrom
        .PARAMETER ValidTo
        .PARAMETER Version
    #>

    [string]$Alias

    [DateTime]$CreationDate

    [string]$EntryType

    [string]$Issuer

    [string]$Owner

    [string]$SerialNumber

    [string]$SHA1Thumbprint

    [string]$SHA256Thumbprint

    [string]$SignatureAlgorithmName

    [string]$SubjectPublicKeyAlgorithm

    [DateTime]$ValidFrom

    [DateTime]$ValidTo

    [string]$Version
}