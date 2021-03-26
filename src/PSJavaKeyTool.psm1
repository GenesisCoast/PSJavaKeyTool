#requires -Version 5.0

class KeyToolCertificate {
    <#

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

function Get-KeyToolTrimmedResult {
    <#
        .SYNOPSIS
            Trims the result from the KeyTool, removing any blank spaces or padding.
        .PARAMETER AsString
            Returns the trimmed result as a string, rather than a string array of lines.
        .PARAMETER Result
            The result to process, can be either a string or a string array of lines.
    #>

    param(
        [Parameter(Mandatory = $false)]
        [switch]
        $AsString,

        [Parameter(
            Mandatory = $true,
            Position  = 0
        )]
        [object]
        $Result
    )

    if ($Result -is [array]) {
        $Result = $Result -join "`n"
    }
    elseif ($Result -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Result)) {
            throw (
                "Cannot validate argument on parameter 'Result'. " +
                "It is either null, empty or whitespace."
            )
        }
    }
    else {
        throw "Only string and an array of strings are supported for the parameter 'Result'."
    }

    $lines = $Result.Trim() -isplit "`n"
    $lines = $lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if ($AsString) {
        return $($lines -join "`n")
    }
    else {
        return $lines
    }
}

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

function ConvertFrom-KeyToolCertificateDetails {
    <#
        .SYNOPSIS
            Parses the certificate details from the KeyTool, into an object.
        .PARAMETER Result
            The result to parse that contains the certificate details.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [string]
        $Result
    )

    $certificateSection = ($Result -split 'Your keystore contains \d+ entries')[1].Trim()
    $certificates = $certificateSection -isplit '\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*'
    $certificateObjects = @()

    foreach ($certificate in $certificates) {
        if (-not [string]::IsNullOrWhiteSpace($certificate)) {
            # Splitup the certificate sub-sections, into details and extensions.
            $subsections = $certificate -isplit "Extensions:"

            # Get the details excluding any blanks spaces.
            $details = Get-KeyToolTrimmedResult $subsections[0] -AsString

            # Split the valid to and from into seperate lines.
            $details = $details -ireplace '(Valid from: [a-zA-Z0-9\: ]+) until: ([a-zA-Z0-9\: ]+)', "`$1 `nValid to: `$2"

            # Process each of the details.
            $certificateObject = [KeyToolCertificate]::new()
            foreach ($detail in $details -isplit "`n") {
                # Get the key value for the detail.
                $keyValue = $detail -isplit ':'

                # Handle values that contain ':'.
                if ($keyValue.Length -gt 2) {
                    $key = $keyValue[0].Trim()
                    $value = ($keyValue[1..$keyValue.Length] -join ':').Trim()
                }
                else {
                    $key = $keyValue[0].Trim()
                    $value = $keyValue[1].Trim()
                }

                # Assign the value to the correct object property.
                switch ($key) {
                    'Alias name' {
                        $certificateObject.Alias = $value
                        break
                    }
                    'Creation date' {
                        $certificateObject.CreationDate = [DateTime]::Parse($value)
                        break
                    }
                    'Entry type' {
                        $certificateObject.EntryType = $value
                        break
                    }
                    'Issuer' {
                        $certificateObject.Issuer = $value
                        break
                    }
                    'Owner' {
                        $certificateObject.Owner = $value
                        break
                    }
                    'Serial number' {
                        $certificateObject.SerialNumber = $value
                        break
                    }
                    'SHA1' {
                        $certificateObject.SHA1Thumbprint = $value -ireplace ':', ''
                        break
                    }
                    'SHA256' {
                        $certificateObject.SHA256Thumbprint = $value -ireplace ':', ''
                        break
                    }
                    'Signature algorithm name' {
                        $certificateObject.SignatureAlgorithmName = $value
                        break
                    }
                    'Subject Public Key Algorithm' {
                        $certificateObject.SubjectPublicKeyAlgorithm = $value
                        break
                    }
                    'Valid from' {
                        $certificateObject.ValidFrom = [DateTime]::ParseExact(
                            $value,
                            'ddd MMM dd hh:mm:ss GMT yyyy',
                            $null
                        )
                        break
                    }
                    'Valid to' {
                        $certificateObject.ValidTo = [DateTime]::ParseExact(
                            $value,
                            'ddd MMM dd hh:mm:ss GMT yyyy',
                            $null
                        )
                        break
                    }
                    'Version' {
                        $certificateObject.Version = $value
                        break
                    }
                }
            }
            $certificateObjects += $certificateObject
        }
    }
    return $certificateObjects
}

function Invoke-KeyTool {
    <#
        .SYNOPSIS
            Invokes the Java KeyTool executable with the relevant arguments.
        .PARAMETER Arguments
            List of string arguments to add to the KeyTool command.
        .PARAMETER CommandName
            Name of the command to execute for the KeyTool.
        .PARAMETER ExcludeParamArguments
            List of param arguments to exclude from the arguments list.
        .PARAMETER ParamArguments
            Hashtable or parameters dictionary to convert into arguments for the
            KeyTool. Allows for the calling function to use $PsBoundParameters.
    #>

    param(
        [Parameter(Mandatory = $false)]
        [string[]]
        $Arguments = @(),

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [string]
        $CommandName,

        [Parameter(Mandatory = $false)]
        [string[]]
        $ExcludeParamArguments = @(),

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]
        $ParamArguments
    )

    $keytool = Get-KeyToolLocation

    # Set a default for the arguments if NULL was supplied.
    if ($null -eq $Arguments) {
        $Arguments = @()
    }

    # Set a default for the exclude param arguments if NULL was supplied.
    if ($null -eq $ExcludeParamArguments) {
        $ExcludeParamArguments = @()
    }

    foreach ($parameter in $ParamArguments.GetEnumerator()) {
        # Should the parameter be excluded?
        if ($null -ne $ExcludeParamArguments -and `
            $ExcludeParamArguments -cnotcontains $parameter.Key
        ) {
            # Is the argument a switch?
            if ($parameter.Value -is [switch] -and $parameter.Value) {
                $paramArguments += "-$($parameter.Key.ToLower())"
            }
            # Any other argument.
            else {
                if (-not [string]::IsNullOrWhiteSpace($parameter.Value)) {
                    $paramArguments += "-$($parameter.Key.ToLower()) '$($parameter.Value)'"
                }
                else {
                    Write-Verbose "Skipped parameter $($parameter.Key) as its value is empty"
                }
            }
        }
    }

    # Invoke keytool.exe
    $result = Invoke-Expression -Command (
        "& $keytool -$CommandName $paramArguments $($Arguments -join ' ') *>&1"
    )

    # Re-surface exception message as standard result, caused by different tool sub-functions.
    if ($result.Exception -and $result.Excepton.Message) {
        $result = $result.Exception.Message
    }

    # Join lines into a cohensive result, caused by different tool sub-functions.
    if ($result -is [array]) {
        $result = $result -join "`n"
    }

    return $result.Trim()
}

function Get-KeyStoreCertificate {
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

Export-ModuleMember -Function *