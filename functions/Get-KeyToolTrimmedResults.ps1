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