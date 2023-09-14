<#
.DESCRIPTION
    --------- DISCLAIMER ---------
            Might not work
             EATER OF RAM
    -------------------------------
    Learning new things - terribly inefficient - don't use this

.PARAMETER BlockListURL
    Fetch list from the world wide web

.PARAMETER BlockListTXT
    Read local file

.PARAMETER ConsolidateGE
    How many subdomains are considered a-okay
    
.PARAMETER OutSkipped
    View skipped entries in terminal, they fly by

.NOTES
    Author: returaxel
    Updated: Almost handles an array of lists, now outputs information without user input
    Planned: Wildcard-Magic

.EXAMPLE
    Might want to output into a variable
        $EatTheOutput = .\regexSUBmission.ps1 -BlockListURL 'https://raw.githubusercontent.com/returaxel/untangleable-json/main/TestList.txt' 

    Multiple lists is asking for trouble, output does function, kinda. Heres how!
        $EatTheOutput = [array]$urls | % {
        .\regexSUBmission.ps1 $_ -BlockListURL $_}
#>

[CmdletBinding(DefaultParametersetName='One')] 
param (
    [Parameter()][string]$ListID = 'Blacklist',
    [Parameter(ParameterSetName='One')][string]$BlockListURL,
    [Parameter(ParameterSetName='Two')][string]$BlockListTXT,
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
        Write-Host `n$PSItem.Exception.Message -ForegroundColor Red
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
        [Parameter()][string]$Regex = '(?!^[\w]*[ ])([\w*-]+)(\b[\w.*-]+)?(\.[\w]+)(?:[\W]*?$)'
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
    $BlockList | ForEach-Object {

        # Skip empty and commented lines, edit regex as needed
        if (-not[string]::IsNullOrWhiteSpace($_) -and (-not[regex]::Match($_,'^!|@|#').Success)) {

            # Add one every time
            $Iteration += 1

            # If there's a domain on the current line it should match here
            # The brain of the operation
            $RegexMatch = [regex]::Matches($_, $Regex)

            # Continue if match
            if (-not[string]::IsNullOrEmpty($RegexMatch)) {
                
# Measure each iteration, added to the next one because of reasons
$RegexOperation = Measure-Command {

                # Full match here or throw errors due to emptiness inside
                $RegexTotal = '{0}{1}{2}' -f [string]$RegexMatch.Groups[1].Value,[string]$RegexMatch.Groups[2].Value,[string]$RegexMatch.Groups[3].Value
                $SLDTLD = '{0}{1}' -f [string]$RegexMatch.Groups[2].Value,[string]$RegexMatch.Groups[3].Value
                $SUBTLD ='{0}{1}' -f [string]$RegexMatch.Groups[1].Value,[string]$RegexMatch.Groups[3].Value

                # Try to avoid unnecessary duplicates
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
                            Write-Host `n$PSItem.Exception.Message -ForegroundColor Red -NoNewline
                            Write-Host " [ $Key ]" -ForegroundColor DarkGray
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
            }

        # Add time to run for iteration
        if (-not[string]::IsNullOrEmpty($Key)) {
            $OutHash['Domains'][$Key].RunTimeMS = $RegexOperation.TotalMilliseconds
        }

        } # Output skipped entries / comments
        elseif ($OutSkipped) {
            $Comments += 1
            Write-Host $_ -ForegroundColor DarkGray
        }

    }

} # END MEASURE full duration

    # Statistics
    $AggregateSUB = [System.Collections.Generic.List[int]]@()

    # Informational: How many domains before wildcard
    # ConsolidateGE sets the subdomain limit for a unique SLD+TLD match
    $OutHash['Domains'].keys | ForEach-Object {
        if ([int]$OutHash['Domains'][$_]['SUB'].Values.Count -ge $ConsolidateGE) {
            [int]$SubdomainTotal += [int]$OutHash['Domains'][$_]['SUB'].Values.Count
            $AggregateSUB.Add([int]$OutHash['Domains'][$_]['SUB'].Values.Count)
        }
    }

    $OutStatistics = ($AggregateSUB | Measure-Object -Minimum -Maximum -Sum -Average | Select-Object -ExcludeProperty Property)

    # Information and statistics in the hashtable
    $OutHash['Info'] = [ordered]@{
        Source = "$([int]$BlockList.Length) entries" # comments and blank included
        Output = "$([int]$OutHash['Domains'].keys.count) entries" # unique only
        Duplicated = "$($AggregateSUB.Count) | sum of SLD+TLD matched more than once" # matched SLD+TLD
        Aggregated = "$([int]$SubdomainTotal) | sum of their children" # subdomain / hosts that have common SLD+TLD parents
        Breakdown = $OutStatistics
        Iterations = "$([int]$Iteration)" # comments excluded
        RunTime = "$($RunTime.TotalSeconds) seconds"
    }

    # Terminal FLUFF
    Write-Host "`n`n`t`t SUMMARY`n##############################################`n" -ForegroundColor DarkCyan
    Write-Host "Read the code comments for some more info" -ForegroundColor DarkGray
    $OutHash['Info'] | ConvertTo-Json -Depth 3 | Out-Host
    Write-Host "##############################################" -ForegroundColor DarkCyan

    $OutHash
    
    # RAM Memorial
    Remove-Variable OutHash, OutStatistics, AggregateSUB
    if ($Iteration -ge 50000) {
        [GC]::Collect()
    }
}

# Attempt to build array out of selected source
# Output need to be caught or bad times be had
if (-not[string]::IsNullOrEmpty($BlockListURL)) {
    RegexMagic -BlockList ((Invoke-WebRequest $BlockListURL -UseBasicParsing).Content -split '\r?\n')
} 
elseif (-not[string]::IsNullOrEmpty($BlockListTXT)) {
    RegexMagic -BlockList (Get-StreamReaderArray -Path $BlockListTXT)
} 
