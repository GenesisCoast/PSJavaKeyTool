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