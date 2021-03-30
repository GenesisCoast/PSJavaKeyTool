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