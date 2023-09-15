<#
.DESCRIPTION
    --------- DISCLAIMER ---------
            Might not work
    -------------------------------
    Input a blocklist to view statistics and consolidate (OPT)
        - Output 
            - json: hashtable with all information (exported: 200k domains ~100MB)
            - psobject: with consolidated unique SLDTLD (everything above subdomain) and subdomain count

.PARAMETER BlockListURL
    Fetch list from the world wide web

.PARAMETER BlockListTXT
    Read local file

.PARAMETER ConsolidateGE
    How many subdomains are considered a-okay

.PARAMETER OutputAs
    Select what to return after ran. 
        info (always): only shows information
        json (opt): hashtable which can be exported as .json 
        psobject (opt): can be exported to shorter list with wildcards
    
.PARAMETER OutSkipped
    View skipped entries in terminal, they fly by

.NOTES
    Author: returaxel
    Version: 1.0.6
    Updated: Now easier on RAM, aggregates subdomains with wilcards and shows information without interaction 

.EXAMPLE
    Might want to output into a variable
        $EatTheOutput = .\regexSUBmission.ps1 -BlockListURL 'https://raw.githubusercontent.com/returaxel/untangleable-json/main/TestList.txt' 

    Multiple lists is asking for trouble but almost functions. Heres how!
        $EatTheOutput = [array]$urls | % {
        .\regexSUBmission.ps1 $_ -BlockListURL $_}
#>

[CmdletBinding(DefaultParametersetName='One')] 
param (
    [Parameter(ParameterSetName='One')][string]$BlockListURL,
    [Parameter(ParameterSetName='Two')][string]$BlockListTXT,
    [ValidateSet('info','json','psobject')][string]$OutputAs = 'info',
    [Parameter()][int]$ConsolidateGE = 5,
    [Parameter()][switch]$OutSkipped
)

function Get-StreamReaderArray {
    # Slap a .TXT into an Array
    param (
        [Parameter()][string]$PathTXT
   )
    # https://blog.dcrich.net/post/2022/powershell-journeyman-generic-collections/#queue
    $GenericList = [System.Collections.Generic.List[string]]@()
        
    try {
        $StreamReader = [System.IO.StreamReader]::New($PathTXT)
    }
    catch {
        Write-Host StreamReader`n$PSItem.Exception.Message -ForegroundColor Red
        Break
    }

    while ($null -ne ($Line = $StreamReader.ReadLine())) {
        $GenericList.Add($Line)
    }

    $StreamReader.Dispose()
    return  $GenericList
}

function RegexMagic {
    param (
        [Parameter()][array]$BlockList,
        [Parameter()][string]$Regex = '^(?>[\d.]+?\ |)([\w*-]+)(\.[\w.*-]+)?(\.[\w-]+)(.*?$)'
    ) 

    # Hashtable
    $OutHash = @{
        Info = [ordered]@{} # Operational info 
        Domains = [ordered]@{} # Domain list
    }

# Measure full duration
$RunTime = Measure-Command { 

    # Count things
    [int]$Iteration = 0

    # Start working your way thru the list
    foreach ($line in $BlockList) {

        # Skip empty and commented lines, edit regex as needed
        if (-not[string]::IsNullOrWhiteSpace($line) -and (-not[regex]::Match($line,'^!|@|#').Success)) {

            # Add one every time
            $Iteration += 1

            # If there's a domain on the current line it should match here
            # The brain of the operation
            $RegexMatch = [regex]::Matches($line, $Regex)

            # Continue if match
            if (-not[string]::IsNullOrEmpty($RegexMatch)) {
                
# Measure each iteration, added to the next one because of reasons
$RegexOperation = Measure-Command {

                # DEBUG: .Groups[4] should match lines with comments after the domain and weird formats
                if (($RegexMatch.Groups[4].Value) -as [bool]) {
                    Write-Host "MatchG4: $line"
                }

                # Values we
                $RegexTotal = '{0}{1}{2}' -f [string]$RegexMatch.Groups[1].Value,[string]$RegexMatch.Groups[2].Value,[string]$RegexMatch.Groups[3].Value
                $SLDTLD = '{0}{1}' -f [string]$RegexMatch.Groups[2].Value,[string]$RegexMatch.Groups[3].Value
                $SUBTLD ='{0}{1}' -f [string]$RegexMatch.Groups[1].Value,[string]$RegexMatch.Groups[3].Value

                try {
                    [bool]$SLD = ($RegexMatch.Groups[2].Value)-as [bool]
                    [string]$Key = switch ($SLD) {
                        $true { $SLDTLD }
                        $false { $SUBTLD }
                    }

                    # Should SLD+TLD exist, add the current keys' subdomain to the existing
                    if ($SLD -and ($OutHash['Domains'][$Key] -as [bool])) {

                       try {
                           $OutHash['Domains'][$Key]['SUB'].Add([string]$RegexMatch.Groups[1].Value,$Iteration)
                       }
                       catch {
                            Write-Host `n$PSItem.Exception.Message -ForegroundColor Red
                            Write-Host "Error: $line" -ForegroundColor DarkGray
                       }
                    }
                    else {                   
                        # If key didn't exist, add now
                        $OutHash['Domains'][$Key] = [ordered]@{
                            # Add to hashtable. Comment out (#) things you don't care about.
                            SUB = [ordered]@{([string]$RegexMatch.Groups[1].Value) = $Iteration} # Sub domain
                            SLD = [string]$RegexMatch.Groups[2].Value # Second level domains - everything between SUB and TLD
                            TLD = [string]$RegexMatch.Groups[3].Value # Top level domain
                            FullMatch = [string]$RegexTotal
                            WellFormed = [Uri]::IsWellFormedUriString($RegexMagic.FullMatch, 'Relative')
                            RunTimeMS = $null
                            Iteration = $Iteration
                        }
                    }

                }
                catch {
                    Write-Host $PSItem.Exception.Message -ForegroundColor DarkRed
                }  
} # END MEASURE (Measured object is added to the next iteration)
            } else {
                Write-Host "NoMatch: $line" -ForegroundColor DarkGray
            }

        # Add time to run for iteration
        if (-not[string]::IsNullOrEmpty($Key)) {
            $OutHash['Domains'][$Key].RunTimeMS = $RegexOperation.TotalMilliseconds
        }

        } # Output skipped entries / comments
        elseif ($OutSkipped) {
            $Comments += 1
            Write-Host $line -ForegroundColor DarkGray
        }

    }

} # END MEASURE full duration

# --------------[ INFORMATION ] --------------

    # ConsolidateGE sets the subdomain limit for a unique SLD+TLD match
    $Aggregated = [System.Collections.Generic.List[PSObject]]@()

    foreach ($domain in $OutHash['Domains'].Keys) {

        [int]$SUBTotal = [int]$OutHash['Domains'][$domain]['SUB'].Values.Count

        # Proceed if subdomain count -GE ConsolidateGE
        if ([int]$SUBTotal -ge $ConsolidateGE) {

            # if ($OutWildcard){ 
            # Add SLD+TLD and the total subdomains for each to an object
                $Aggregated.Add([PSCustomObject]@{Domain = ('*{0}' -f $domain);SUBTotal = $SUBTotal})
            # }
        }
    }

    $OutStatistics = ($Aggregated.SubTotal | Measure-Object -Minimum -Maximum -Sum -Average)

    # Information and statistics in the hashtable
    $OutHash['Info'] = [ordered]@{
        Source = "$([int]$BlockList.Length) entries" # comments and blank included
        Output = "$([int]$OutHash['Domains'].keys.count) entries" # unique only
        Duplicated = "$($Aggregated.Domain.Count) | sum of SLD+TLD with more than $($ConsolidateGE) subdomains" # matched SLD+TLD
        Aggregated = "$([int]$OutStatistics.Sum) | sum of their children" # subdomain / hosts that have common SLD+TLD parents
        Breakdown = $OutStatistics
        Iterations = "$([int]$Iteration)" # comments excluded
        RunTime = "$($RunTime.TotalSeconds) seconds"
    }

    # -------------- [ OUTPUT ] --------------

    Write-Host "`n`n`t`t SUMMARY`n##############################################`n" -ForegroundColor DarkCyan
    switch ($OutputAs) {
        json    { $OutHash }
        psobject{ $Aggregated }
        default { Write-Host "Default output: information"}
        }

    Write-Host "Visit github ReadMe for more information" -ForegroundColor DarkGray
    $OutHash['Info'] | ConvertTo-Json -Depth 3 | Out-Host
    Write-Host "##############################################" -ForegroundColor DarkCyan

# -------------- [ CLEANUP ] --------------

    # RAM Memorial
    Remove-Variable OutHash, OutStatistics, Aggregated
    if ($Iteration -ge 50000) {
        [GC]::Collect()
    }
}

# -------------- [ SCRIPT ] --------------
# Makes an array of input (or throw error) and send it thru RegexMagic
if (-not[string]::IsNullOrEmpty($BlockListURL)) {
    RegexMagic -BlockList ((Invoke-WebRequest $BlockListURL -UseBasicParsing).Content -split '\r?\n')
} 
elseif (-not[string]::IsNullOrEmpty($BlockListTXT)) {
    RegexMagic -BlockList (Get-StreamReaderArray -Path $BlockListTXT)
}
