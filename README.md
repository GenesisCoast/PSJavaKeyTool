# PSJavaKeyTool

PSJavaKeyTool is a PowerShell wrapper for the Java keytool.exe executable. This module was originally created for use with the DSC resource (to-be built), however it can also be used standalone.

## Types

The following custom types have been created for the module.

### KeyToolCertificate

The `KeyToolCertificate` type was created to provide an explicit type for all of the certificate details that are retrieved during the `Get-KeyToolCertificate` function. Eventually the type will be utilized in another functions in order to facilatate piping.

The type has the following properties:

| Name | Type | Description |
|------|------|-------------|
| Alias | `string` | The alias of the certificate in the specified KeyStore.
| CreationDate | `DateTime` |
| EntryType | `string` |
| Issuer | `string` |
| Owner | `string` |
| SerialNumber | `string` |
| SHA1Thumbprint | `string` |
| SHA256Thumbprint | `string` |
| SignatureAlgorithmName | `string` |
| SubjectPublicKeyAlgorithm | `string` |
| ValidFrom | `DateTime` |
| ValidTo | `DateTime` |
| Version | `string` |

## Functions

### Get-KeyToolTrimmedResult

### Get-KeyToolLocation

### ConvertFrom-KeyToolCertificateDetails

### Invoke-KeyTool

### Get-KeyStoreCertificate

### Import-KeyToolCertificate

### Import-KeyToolStore

### Remove-KeyToolCertificate

### Set-KeyToolCertificateAlias

## Contribution

