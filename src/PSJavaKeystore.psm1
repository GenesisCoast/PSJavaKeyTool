function Get-KeyToolLocation {
    $packages = Get-Package `
        | Where-Object { $_.Name -like "*Java*" -or $_.Name -like "*Oracle*" } `
        | Sort-Object -Descending -Property 'Version'

    foreach ($package in $packages) {
        $keytool = Get-ChildItem `
            -Filter 'keytool.exe' `
            -Path $package.Source `
            -Recurse

        if ($null -ne $keytool) {
            return $keytool.FullName
        }
        else {
            throw (
                'Could not find a version of Java that has keytool.exe, ' +
                'please install a version of the development kit.'
            )
        }
    }
}

function Invoke-KeyTool {
    param(
        [Parameter(Mandatory = $false)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [string[]]
        $Arguments = $null,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [string]
        $CommandName,

        [Parameter(Mandatory = $false)]
        [string[]]
        $ExcludeParameterNames,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSBoundParametersDictionary]
        $ParamArguments
    )

    $keytool = Get-KeyToolLocation

    foreach ($parameter in $ParamArguments.GetEnumerator()) {
        # Should the parameter be excluded?
        if ($ExcludeParameterNames -cnotcontains $parameter.Key) {
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

    $result = Invoke-Expression (
        "& $keytool -$CommandName $paramArguments $($arguments -join ' ') *>&1"
    )

    if ($result.Exception -and $result.Excepton.Message) {
        $result = $result.Exception.Message
    }

    return $result
}

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
            Get-JavaKeyStoreCertificate `
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
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
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
        -CommandName 'list' `
        -Parameters $PSBoundParameters

    switch -Wildcard ($result -join "`n") {
        '*Your keystore contains*' {
            $section = ($result -isplit 'entries')[1].Trim()
            $lines = $section -isplit "`n"
            break
        }
        '*Certificate fingerprint*' {
            $lines = $certificateSection -isplit "`n"
        }
        default {
            throw $result
        }
    }

    $certificates = @()

    for ($i = 0; $i -lt $lines.Count; $i = $i + 2) {
        $certificates.Add(@{
            'Alias' = ($lines[$i] -isplit ',')[0].Trim();
            'ImportDate' = [DateTime]::Parse($lines[$i] -isplit ',')[1].Trim();
            'Thumbprint' = ($lines[$i + 1] -isplit ': ')[1].Replace(':', '').Trim()
        })
    }

    return $certificates
}

function Import-KeyToolCertificate {
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
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
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
            '-noprompt',
            '-v'
        ) `
        -CommandName 'importcert' `
        -ParamArguments $PSBoundParameters

    switch -Wildcard ($result) {
        'Certificate was added to keystore*' {
            return Get-KeyToolCertificate `
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

function Import-KeyToolStore{
    param(
        [Parameter(Mandatory = $false)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('DestinationAlias')]
        [string]
        $DestAlias,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('DestinationKeyStore')]
        [string]
        $DestKeyStore,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('DestinationStorePass')]
        [string]
        $DestStorePass,

        [Parameter(Mandatory = $false)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('DestinationKeyStoreType')]
        [string]
        $DestKeyStoreType,

        [Parameter(Mandatory = $false)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('SourceAlias')]
        [string]
        $SrcAlias,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('SourceKeyStore')]
        [string]
        $SrcKeyStore,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('SourceStorePass')]
        [string]
        $SrcStorePass,

        [Parameter(Mandatory = $false)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [Alias('SourceKeyStoreType')]
        [string]
        $SrcKeyStoreType
    )

    if ($SrcStorePass -ne $DestStorePass) {
        Write-Warning 'The two store passes do not match, this may could compatibility issues dpending on your use case.'
    }

    $result = Invoke-KeyTool `
        -Arguments @(
            '-v'
        ) `
        -CommandName 'importkeystore' `
        -ParamArguments $PSBoundParameters

    switch -Wildcard ($result) {
        'Certificate was added to keystore*' {
            return Get-KeyToolCertificate `
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

function Remove-KeyToolCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
        [string]
        $Alias,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
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
        [ValidateScript({ -not [string]::IsNullOrWhitespace($_) })]
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
            return Get-KeyToolCertificate `
                -Alias $DestAlias `
                -KeyStore $KeyStore `
                -StorePass $StorePass `
                -StoreType $StoreType
        }
        default {
            throw $result
        }
    }
}
