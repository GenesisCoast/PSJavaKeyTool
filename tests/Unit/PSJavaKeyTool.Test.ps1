<#

#>

#requires -Modules Pester

$NullAndWhitespaceTestCases = @{
    'TestCases' = @(
        @{ 'Value' = $null },
        @{ 'Value' = '' },
        @{ 'Value' = ' ' },
        @{ 'Value' = '    ' }
    )
}

$ModuleName = 'PSJavaKeyTool'

Import-Module "$PSScriptRoot\..\..\src\$ModuleName.psm1"

InModuleScope $ModuleName {
    Describe 'Get-KeyToolTrimmedResult' {
        Context 'when the function parameters are invalid' {
            It 'should throw an exception when "-Result" is null, empty or whitespace' @NullAndWhitespaceTestCases {
                param(
                    [string]
                    $Value
                )

                # Act
                $act = {
                    Get-KeyToolTrimmedResult -Result $Value
                }

                # Assert
                $act | Should -Throw "Cannot validate argument on parameter 'Result'. It is either null, empty or whitespace."
            }

            It 'should throw an exception when "-Result" is not a string or array' {
                # Act
                $act = {
                    Get-KeyToolTrimmedResult -Result ([DateTime]::Now)
                }

                # Assert
                $act | Should -Throw "Only string and an array of strings are supported for the parameter 'Result'."
            }
        }

        Context 'when the function parameters are valid' {
            It 'should return a trimmed result, when result is a string' {
                # Arrange
                $details = Get-Content "$PSScriptRoot/CertificateDetailsResult.txt" -Raw

                # Act
                $lines = Get-KeyToolTrimmedResult $details

                # Assert
                foreach ($line in $lines) {
                    $line | Should -Not -BeNullOrEmpty
                }
            }
        }
    }

    Describe 'Get-KeyToolLocation' -Skip {
        It 'should throw an exception when keytool.exe cannot be found' {
            # Arrange
            Mock 'Get-ItemProperty' {
                return @{
                    'DisplayName' = 'Java';
                    'DisplayVersion' = '1.16.0.0';
                    'InstallLocation' = 'C:\Program Files\Java\jdk-16';
                }
            }
            Mock 'Get-ChildItem' {
                return $null
            }

            # Act
            $act = {
                Get-KeyToolLocation
            }

            # Assert
            $act | Should -Throw 'Could not find a version of Java that contains keytool.exe*'
        }

        It 'should NOT throw an exception when keytool.exe is found' {
            # Arrange
            Mock 'Get-ItemProperty' {
                return @(
                    @{
                        'DisplayName' = 'Java';
                        'DisplayVersion' = '1.16.0.0';
                        'InstallLocation' = 'C:\Program Files\Java\jdk-16';
                    }
                )
            }
            Mock 'Get-ChildItem' {
                return @(
                    @{
                        'FullName' = 'C:\Program Files\Java\jdk-16\bin\keytool.exe'
                    }
                )
            }

            # Act
            $act = {
                Get-KeyToolLocation
            }

            # Assert
            $act | Should -Not -Throw 'Could not find a version of Java that contains keytool.exe*'
        }

        $VersionTestCases = @{
            'TestCases' = @(
                @{
                    'NewestVersion' = '1.18.0.0';
                    'OldestVersion' = '1.16.0.0';
                },
                @{
                    'NewestVersion' = '1.18.12.0';
                    'OldestVersion' = '1.18.12.1';
                },
                @{
                    'NewestVersion' = '2.16.0.0';
                    'OldestVersion' = '1.18.0.0';
                },
                @{
                    'NewestVersion' = '1.18.2.0';
                    'OldestVersion' = '1.16.20.0';
                }
            )
        }

        It 'should return the path for the newest keytool.exe version' @VersionTestCases {
            param(
                [string]
                $NewestVersion,

                [string]
                $OldestVersion
            )

            # Arrange
            $newestVersionInstallLocation = 'C:\Program Files\Java\jdk-18'
            $oldestVersionInstallLocation = 'C:\Program Files\Java\jdk-16'
            $keyToolLocation = 'C:\Program Files\Java\jdk-16\bin\keytool.exe'
            Mock 'Get-ItemProperty' {
                return @(
                    @{
                        'DisplayName' = "Java-$NewestVersion";
                        'DisplayVersion' = $NewestVersion;
                        'InstallLocation' = $newestVersionInstallLocation;
                    },
                    @{
                        'DisplayName' = "Java-$OldestVersion";
                        'DisplayVersion' = $OldestVersion;
                        'InstallLocation' = $oldestVersionInstallLocation;
                    }
                )
            }
            Mock 'Get-ChildItem' {
                return @(
                    @{
                        'FullName' = $keyToolLocation
                    }
                )
            }

            # Act
            $result = Get-KeyToolLocation

            # Assert
            $result | Should -Be $keyToolLocation

            Assert-MockCalled `
                -CommandName 'Get-ChildItem' `
                -ExclusiveFilter {
                    Write-Output $Path;
                    $Path -eq $newestVersionInstallLocation
                } `
                -Times 1
        }

        It 'should return the path for the newest keytool.exe version, when there are multiple' {
            # Arrange
            $newestInstallLocation = 'C:\Program Files\Java\jdk-20'
            $keyToolLocation = 'C:\Program Files\Java\jdk-20\bin\keytool.exe'
            Mock 'Get-ItemProperty' {
                return @(
                    @{
                        'DisplayName' = "Java-1.19.2.0";
                        'DisplayVersion' = '1.19.2.0';
                        'InstallLocation' = 'C:\Program Files\Java\jdk-19';
                    },
                    @{
                        'DisplayName' = "Java-1.16.5.8";
                        'DisplayVersion' = '1.16.5.8';
                        'InstallLocation' = 'C:\Program Files\Java\jdk-16';
                    },
                    @{
                        'DisplayName' = "Java-1.20.5.8";
                        'DisplayVersion' = '1.20.5.8';
                        'InstallLocation' = $newestInstallLocation;
                    },
                    @{
                        'DisplayName' = "Java-1.7.0.0";
                        'DisplayVersion' = '1.7.0.0';
                        'InstallLocation' = 'C:\Program Files\Java\jdk-7';
                    }
                )
            }
            Mock 'Get-ChildItem' {
                return @(
                    @{
                        'FullName' = $keyToolLocation
                    }
                )
            }

            # Act
            $result = Get-KeyToolLocation

            # Assert
            $result | Should -Be $keyToolLocation

            Assert-MockCalled `
                -CommandName 'Get-ChildItem' `
                -ExclusiveFilter {
                    Write-Output $Path;
                    $Path -eq $newestVersionInstallLocation
                } `
                -Times 1
        }
    }

    Describe 'ConvertFrom-KeyToolCertificateDetails' {
        Context 'when the parameters are invalid' {
            It 'should throw an exception when the parameter -Result is null, empty or whitespace' @NullAndWhitespaceTestCases {
                param(
                    [string]
                    $Value
                )

                # Act
                $act = {
                    ConvertFrom-KeyToolCertificateDetails -Result $Value
                }

                # Assert
                $act | Should -Throw "Cannot validate argument on parameter 'Result'*"
            }
        }

        Context 'when the parameters are valid' {
            It 'should retrieve details for a single certificate' {
                # Arrange
                $alias = 'subroot'
                $creationDate = '26 Mar 2021'
                $entryType = 'trustedCertEntry'
                $owner = 'CN=GlobalSign RSA OV SSL CA 2018, O=GlobalSign nv-sa, C=BE'
                $issuer = 'CN=GlobalSign, O=GlobalSign, OU=GlobalSign Root CA - R3'
                $serialNumber = '1ee5f221dfc623bd4333a8557'
                $validFrom = 'Wed Nov 21 00:00:00 GMT 2018'
                $validTo = 'Tue Nov 21 00:00:00 GMT 2028'
                $sha1Thumbprint = 'DF:E8:30:23:06:2B:99:76:82:70:8B:4E:AB:8E:81:9A:FF:5D:97:75'
                $sha256Thumbprint = 'B6:76:FF:A3:17:9E:88:12:09:3A:1B:5E:AF:EE:87:6A:E7:A6:AA:F2:31:07:8D:AD:1B:FB:21:CD:28:93:76:4A'
                $signatureAlgorithmName = 'SHA256withRSA'
                $subjectPublicKeyAlgorithm = '2048-bit RSA key'
                $version = '3'
                $details = @"
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 4 entries

Alias name: $alias
Creation date: $creationDate
Entry type: $entryType

Owner: $owner
Issuer: $issuer
Serial number: $serialNumber
Valid from: $validFrom until: $validTo
Certificate fingerprints:
            SHA1: $sha1Thumbprint
            SHA256: $sha256Thumbprint
Signature algorithm name: $signatureAlgorithmName
Subject Public Key Algorithm: $subjectPublicKeyAlgorithm
Version: $version

Extensions:

#1: ObjectId: 1.3.6.1.5.5.7.1.1 Criticality=false
AuthorityInfoAccess [
    [
    accessMethod: ocsp
    accessLocation: URIName: http://ocsp2.globalsign.com/rootr3
]
]

#2: ObjectId: 2.5.29.35 Criticality=false
AuthorityKeyIdentifier [
KeyIdentifier [
0000: 8F F0 4B 7F A8 2E 45 24   AE 4D 50 FA 63 9A 8B DE  ..K...E$.MP.c...
0010: E2 DD 1B BC                                        ....
]
]

#3: ObjectId: 2.5.29.19 Criticality=true
BasicConstraints:[
    CA:true
    PathLen:0
]

#4: ObjectId: 2.5.29.31 Criticality=false
CRLDistributionPoints [
    [DistributionPoint:
        [URIName: http://crl.globalsign.com/root-r3.crl]
]]

#5: ObjectId: 2.5.29.32 Criticality=false
CertificatePolicies [
    [CertificatePolicyId: [2.5.29.32.0]
[PolicyQualifierInfo: [
    qualifierID: 1.3.6.1.5.5.7.2.1
    qualifier: 0000: 16 26 68 74 74 70 73 3A   2F 2F 77 77 77 2E 67 6C  .&https://www.gl
0010: 6F 62 61 6C 73 69 67 6E   2E 63 6F 6D 2F 72 65 70  obalsign.com/rep
0020: 6F 73 69 74 6F 72 79 2F                            ository/

]]  ]
]

#6: ObjectId: 2.5.29.15 Criticality=true
KeyUsage [
    DigitalSignature
    Key_CertSign
    Crl_Sign
]

#7: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: F8 EF 7F F2 CD 78 67 A8   DE 6F 8F 24 8D 88 F1 87  .....xg..o.$....
0010: 03 02 B3 EB                                        ....
]
]



*******************************************
*******************************************
"@

                # Act
                $result = ConvertFrom-KeyToolCertificateDetails $details

                # Assert
                $result[0].Alias | Should -Be $alias
                $result[0].CreationDate.ToString() | Should -Be ([DateTime]::Parse($creationDate).ToString())
                $result[0].EntryType | Should -Be $entryType
                $result[0].Issuer | Should -Be $issuer
                $result[0].SerialNumber | Should -Be $serialNumber
                $result[0].SHA1Thumbprint | Should -Be $sha1Thumbprint.Replace(':', '')
                $result[0].SHA256Thumbprint | Should -Be $sha256Thumbprint.Replace(':', '')
                $result[0].SignatureAlgorithmName | Should -Be $signatureAlgorithmName
                $result[0].SubjectPublicKeyAlgorithm | Should -Be $subjectPublicKeyAlgorithm
                $result[0].ValidFrom | Should -Be $([DateTime]::ParseExact(
                    $validFrom,
                    'ddd MMM dd hh:mm:ss GMT yyyy',
                    $null
                ))
                $result[0].ValidTo | Should -Be $([DateTime]::ParseExact(
                    $validTo,
                    'ddd MMM dd hh:mm:ss GMT yyyy',
                    $null
                ))
                $result[0].Version | Should -Be $version
            }

            It 'should retrieve details for multiple certificates' {
                # Act
                $rootAlias = 'root'
                $rootCreationDate = '26 Mar 2021'
                $rootEntryType = 'trustedCertEntry'
                $rootOwner = 'CN=GlobalSign, O=GlobalSign, OU=GlobalSign Root CA - R3'
                $rootIssuer = 'CN=GlobalSign, O=GlobalSign, OU=GlobalSign Root CA - R3'
                $rootSerialNumber = '4000000000121585308a2'
                $rootValidFrom = 'Wed Mar 18 10:00:00 GMT 2009'
                $rootValidTo = 'Sun Mar 18 10:00:00 GMT 2029'
                $rootSha1Thumbprint = 'D6:9B:56:11:48:F0:1C:77:C5:45:78:C1:09:26:DF:5B:85:69:76:AD'
                $rootSha256Thumbprint = 'CB:B5:22:D7:B7:F1:27:AD:6A:01:13:86:5B:DF:1C:D4:10:2E:7D:07:59:AF:63:5A:7C:F4:72:0D:C9:63:C5:3B'
                $rootSignatureAlgorithmName = 'SHA256withRSA'
                $rootSubjectPublicKeyAlgorithm = '2048-bit RSA key'
                $rootVersion = '3'
                $subrootAlias = 'subroot'
                $subrootCreationDate = '26 Mar 2021'
                $subrootEntryType = 'trustedCertEntry'
                $subrootOwner = 'CN=GlobalSign RSA OV SSL CA 2018, O=GlobalSign nv-sa, C=BE'
                $subrootIssuer = 'CN=GlobalSign, O=GlobalSign, OU=GlobalSign Root CA - R3'
                $subrootSerialNumber = '1ee5f221dfc623bd4333a8557'
                $subrootValidFrom = 'Wed Nov 21 00:00:00 GMT 2018'
                $subrootValidTo = 'Tue Nov 21 00:00:00 GMT 2028'
                $subrootSha1Thumbprint = 'DF:E8:30:23:06:2B:99:76:82:70:8B:4E:AB:8E:81:9A:FF:5D:97:75'
                $subrootSha256Thumbprint = 'B6:76:FF:A3:17:9E:88:12:09:3A:1B:5E:AF:EE:87:6A:E7:A6:AA:F2:31:07:8D:AD:1B:FB:21:CD:28:93:76:4A'
                $subrootSignatureAlgorithmName = 'SHA256withRSA'
                $subrootSubjectPublicKeyAlgorithm = '2048-bit RSA key'
                $subrootVersion = '3'
                $details = @"
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 2 entries

Alias name: $rootAlias
Creation date: $rootCreationDate
Entry type: $rootEntryType

Owner: $rootOwner
Issuer: $rootIssuer
Serial number: $rootSerialNumber
Valid from: $rootValidFrom until: $rootValidTo
Certificate fingerprints:
         SHA1: $rootSha1Thumbprint
         SHA256: $rootSha256Thumbprint
Signature algorithm name: $rootSignatureAlgorithmName
Subject Public Key Algorithm: $rootSubjectPublicKeyAlgorithm
Version: $rootVersion

Extensions:

#1: ObjectId: 2.5.29.19 Criticality=true
BasicConstraints:[
  CA:true
  PathLen:2147483647
]

#2: ObjectId: 2.5.29.15 Criticality=true
KeyUsage [
  Key_CertSign
  Crl_Sign
]

#3: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 8F F0 4B 7F A8 2E 45 24   AE 4D 50 FA 63 9A 8B DE  ..K...E$.MP.c...
0010: E2 DD 1B BC                                        ....
]
]



*******************************************
*******************************************

Alias name: $subrootAlias
Creation date: $subrootCreationDate
Entry type: $subrootEntryType

Owner: $subrootOwner
Issuer: $subrootIssuer
Serial number: $subrootSerialNumber
Valid from: $subrootValidFrom until: $subrootValidTo
Certificate fingerprints:
            SHA1: $subrootSha1Thumbprint
            SHA256: $subrootSha256Thumbprint
Signature algorithm name: $subrootSignatureAlgorithmName
Subject Public Key Algorithm: $subrootSubjectPublicKeyAlgorithm
Version: $subrootVersion

Extensions:

#1: ObjectId: 1.3.6.1.5.5.7.1.1 Criticality=false
AuthorityInfoAccess [
    [
    accessMethod: ocsp
    accessLocation: URIName: http://ocsp2.globalsign.com/rootr3
]
]

#2: ObjectId: 2.5.29.35 Criticality=false
AuthorityKeyIdentifier [
KeyIdentifier [
0000: 8F F0 4B 7F A8 2E 45 24   AE 4D 50 FA 63 9A 8B DE  ..K...E$.MP.c...
0010: E2 DD 1B BC                                        ....
]
]

#3: ObjectId: 2.5.29.19 Criticality=true
BasicConstraints:[
    CA:true
    PathLen:0
]

#4: ObjectId: 2.5.29.31 Criticality=false
CRLDistributionPoints [
    [DistributionPoint:
        [URIName: http://crl.globalsign.com/root-r3.crl]
]]

#5: ObjectId: 2.5.29.32 Criticality=false
CertificatePolicies [
    [CertificatePolicyId: [2.5.29.32.0]
[PolicyQualifierInfo: [
    qualifierID: 1.3.6.1.5.5.7.2.1
    qualifier: 0000: 16 26 68 74 74 70 73 3A   2F 2F 77 77 77 2E 67 6C  .&https://www.gl
0010: 6F 62 61 6C 73 69 67 6E   2E 63 6F 6D 2F 72 65 70  obalsign.com/rep
0020: 6F 73 69 74 6F 72 79 2F                            ository/

]]  ]
]

#6: ObjectId: 2.5.29.15 Criticality=true
KeyUsage [
    DigitalSignature
    Key_CertSign
    Crl_Sign
]

#7: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: F8 EF 7F F2 CD 78 67 A8   DE 6F 8F 24 8D 88 F1 87  .....xg..o.$....
0010: 03 02 B3 EB                                        ....
]
]



*******************************************
*******************************************
"@

                # Assert
                $result = ConvertFrom-KeyToolCertificateDetails $details

                # Arrange
                $result[0].Alias | Should -Be $rootAlias
                $result[0].CreationDate.ToString() | Should -Be ([DateTime]::Parse($rootCreationDate).ToString())
                $result[0].EntryType | Should -Be $rootEntryType
                $result[0].Issuer | Should -Be $rootIssuer
                $result[0].SerialNumber | Should -Be $rootSerialNumber
                $result[0].SHA1Thumbprint | Should -Be $rootSha1Thumbprint.Replace(':', '')
                $result[0].SHA256Thumbprint | Should -Be $rootSha256Thumbprint.Replace(':', '')
                $result[0].SignatureAlgorithmName | Should -Be $rootSignatureAlgorithmName
                $result[0].SubjectPublicKeyAlgorithm | Should -Be $rootSubjectPublicKeyAlgorithm
                $result[0].ValidFrom | Should -Be $([DateTime]::ParseExact(
                    $rootValidFrom,
                    'ddd MMM dd hh:mm:ss GMT yyyy',
                    $null
                ))
                $result[0].ValidTo | Should -Be $([DateTime]::ParseExact(
                    $rootValidTo,
                    'ddd MMM dd hh:mm:ss GMT yyyy',
                    $null
                ))
                $result[0].Version | Should -Be $rootVersion

                $result[1].Alias | Should -Be $subrootAlias
                $result[1].CreationDate.ToString() | Should -Be ([DateTime]::Parse($subrootCreationDate).ToString())
                $result[1].EntryType | Should -Be $subrootEntryType
                $result[1].Issuer | Should -Be $subrootIssuer
                $result[1].SerialNumber | Should -Be $subrootSerialNumber
                $result[1].SHA1Thumbprint | Should -Be $subrootSha1Thumbprint.Replace(':', '')
                $result[1].SHA256Thumbprint | Should -Be $subrootSha256Thumbprint.Replace(':', '')
                $result[1].SignatureAlgorithmName | Should -Be $subrootSignatureAlgorithmName
                $result[1].SubjectPublicKeyAlgorithm | Should -Be $subrootSubjectPublicKeyAlgorithm
                $result[1].ValidFrom | Should -Be $([DateTime]::ParseExact(
                    $subrootValidFrom,
                    'ddd MMM dd hh:mm:ss GMT yyyy',
                    $null
                ))
                $result[1].ValidTo | Should -Be $([DateTime]::ParseExact(
                    $subrootValidTo,
                    'ddd MMM dd hh:mm:ss GMT yyyy',
                    $null
                ))
                $result[1].Version | Should -Be $subrootVersion
            }
        }
    }

    Describe 'Invoke-KeyTool' {
        Context 'when the parameters are invalid' {
            BeforeAll {
                Mock 'Get-KeyToolLocation' {}
                Mock 'Invoke-Expression' {
                    return [string]::Empty
                }
            }

            It 'should throw an exception when -CommandName is null, empty or whitespace' @NullAndWhitespaceTestCases {
                param(
                    [string]
                    $Value
                )

                # Act
                $act = {
                    Invoke-KeyTool `
                        -CommandName $Value `
                        -ParamArguments @{
                            'Hello' = 'World'
                        }
                }

                # Assert
                $act | Should -Throw "Cannot validate argument on parameter 'CommandName'*"
            }

            It 'should NOT throw an exception when -Arguments is null' {
                param(
                    [string]
                    $Value
                )

                # Arrange
                $arguments = $null

                # Act
                $act = {
                    Invoke-KeyTool `
                        -Arguments $arguments `
                        -CommandName 'test' `
                        -ParamArguments @{
                            'Hello' = 'World'
                        }
                }

                # Assert
                $act | Should -Not -Throw "Cannot validate argument on parameter 'Arguments'*"
            }

            It 'should NOT throw an exception when -ExcludeParamArguments is null' {
                param(
                    [string]
                    $Value
                )

                # Arrange
                $excludeParamArguments = $null

                # Act
                $act = {
                    Invoke-KeyTool `
                        -CommandName 'test' `
                        -ExcludeParamArguments $excludeParamArguments `
                        -ParamArguments @{
                            'Hello' = 'World'
                        }
                }

                # Assert
                $act | Should -Not -Throw "Cannot validate argument on parameter 'ExcludeParamArguments'*"
            }

            It 'should throw an exception when -ParamArguments is null' {
                param(
                    [string]
                    $Value
                )

                # Act
                $act = {
                    Invoke-KeyTool `
                        -CommandName 'test' `
                        -ParamArguments $null
                }

                # Assert
                $act | Should -Throw "Cannot validate argument on parameter 'ParamArguments'*"
            }
        }
    }
}