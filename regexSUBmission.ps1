<#
.DESCRIPTION
    --------- DISCLAIMER ---------
            Might not work
             EATER OF RAM
    -------------------------------
    Learning new things - terribly inefficient - don't use this

.PARAMETER BlockListURL
    Fetch a list from the world wide web

.PARAMETER BlockListTXT
    Read from local file
    
.PARAMETER OutSkipped
    View skipped entries in terminal, they fly by

.NOTES
    Author: returaxel
    Updated: Trying hashtable things.
        3 capture groups; SUB, SLD, TLD. Second-Level should hold everything except SUB and Top-Level.

.EXAMPLE
    Might want to output into a variable
        $EatTheOutput = .\untangleable-webfilter.ps1 -BlockListURL 'https://raw.githubusercontent.com/returaxel/untangleable-json/main/TestList.txt' 

    Should the list be enormous, might want to output only the duplicate list
        $EatTheOutput = .\untangleable-webfilter.ps1 -BlockListURL 'https://raw.githubusercontent.com/returaxel/untangleable-json/main/TestList.txt' 
        $EatTheOutput.Duplicate | ConvertTo-Json | Set-Content <path_here>
#>

[CmdletBinding(DefaultParametersetName='One')] 
param (
    [Parameter(ParameterSetName='One')][string]$BlockListURL,
    [Parameter(ParameterSetName='Two')][string]$BlockListTXT,
    [Parameter()][switch]$OutSkipped
)

function Get-StreamReaderArray {
    # Slap a .TXT into an Array
    param (
        [Parameter()][string]$PathTXT
   )
    # https://blog.dcrich.net/post/2022/powershell-journeyman-generic-collections/#queue
    $GenericList = [System.Collections.Generic.List[string]]@()

$MeasurePanda = Measure-Command {
        
    $StreamReader = [System.IO.StreamReader]::New($PathTXT)

    while ($null -ne ($Line = $StreamReader.ReadLine())) {
        $GenericList.Add($Line)
    }

}   
    # Write-Host "Import-BlockListTXT.RunTime: $($MeasurePanda.TotalSeconds)s"

    $StreamReader.Dispose()
    return  $GenericList

}

function RegexMagic {
    param (
        [Parameter()][array]$BlockList,
        [Parameter()][string]$Regex = '(?!^[\w]*[ ])([\w*-]+)(\b[\w.*-]+)?(\.[\w]+)(?:[\W]*?$)',
        [Parameter()][int]$Iteration = 0
    ) 

    # Hashtable
    $OutHash = @{
        Host = [ordered]@{}
        Duplicate = [ordered]@{}
    }

# Measure full duration
$RunTime = Measure-Command { 

    # Start working your way thru the list
    $BlockList | ForEach-Object {

# Measure each iteration, added to the next one because of reasons
$RegexOperation = Measure-Command { 

        # Skip empty and commented lines, edit regex as needed
        if (-not[string]::IsNullOrWhiteSpace($_) -and (-not[regex]::Match($_,'^!|@|#').Success)) {
    
            # Add one every time
            $Iteration += 1

            # If there's a domain on the current line it should match here
            # The brain of the operation
            $RegexMatch = [regex]::Matches($_, $Regex)

            # Continue if match
            if (-not[string]::IsNullOrEmpty($RegexMatch)) {

                # Find out what the subdomain is
                try {
                    $Key = if ([string]::IsNullOrEmpty($RegexMatch.Groups[2])) {
                        '{0}{1}' -f $RegexMatch.Groups[1].Value,$RegexMatch.Groups[3].Value
                    } 
                    else {
                        '{0}{1}' -f $RegexMatch.Groups[2].Value,$RegexMatch.Groups[3].Value
                    }

                    # If the SLD+TLD was already in OutHash keys, add the current keys' subdomain to the existing
                    if ($OutHash.Host[$Key] -as [bool]) {

                        try {
                            $OutHash.Host[$Key].SUB.Add([string]$RegexMatch.Groups[1], $Iteration)
                        }
                        catch {
                            Write-Host "HashTable.Host[key].SUB.Add()_Flip: $($OutHash.Host[$Key].URL)" -ForegroundColor DarkYellow
                            Write-Host $PSItem.Exception.Message -ForegroundColor DarkRed
                        }

                        # Separate duplicate keyset, to eat more RAM
                        if ($OutHash.Duplicate[$Key] -as [bool]) {
                            try {
                                $OutHash.Duplicate[$Key].Add([string]$RegexMatch.Groups[1], $Iteration)
                            }
                            catch {
                                Write-Host "HashTable.Host[key].Duplicate.Add()_Flip: $($OutHash.Host[$Key].URL)" -ForegroundColor DarkYellow
                                Write-Host $PSItem.Exception.Message -ForegroundColor DarkRed
                            }
                        } else {
                            $OutHash.Duplicate[$Key] = [ordered]@{ 
                                [string]$RegexMatch.Groups[1] = $Iteration
                            }
                        }

                    }
                    else {
                        # If the key didn't exist, add new entry
                        $OutHash.Host[$Key] = [ordered]@{
                            # Add to hashtable. Comment out (#) things you don't care about.
                            URL = $_
                            SUB = [ordered]@{[string]$RegexMatch.Groups[1].Value = $null} # Sub domain
                            SLD = [string]$RegexMatch.Groups[2].Value # Second level domains - everything between SUB and TLD
                            TLD = [string]$RegexMatch.Groups[3].Value # Top level domain
                            FullMatch = '{0}{1}{2}' -f $RegexMatch.Groups[1].Value,$RegexMatch.Groups[2].Value,$RegexMatch.Groups[3].Value
                            WellFormed = [Uri]::IsWellFormedUriString($RegexMagic.FullMatch, 'Relative')
                            Iteration = $Iteration
                            RegexTimeMS = $RegexOperation.TotalMilliseconds
                        }
                    }

                }
                catch {
                    Write-Host 'HashTable_Flip.()' -ForegroundColor DarkYellow
                    Write-Host $PSItem.Exception.Message -ForegroundColor DarkRed
                }  
            }

        } # Output skipped entries / comments
        elseif ($OutSkipped) {
            Write-Host $_ -ForegroundColor DarkGray
        }

} # END MEASURE (Measured object is added to the next iteration)

    }
} # END MEASURE full duration

    # Output some info
    Write-Host "`n"
    Write-Host "`n Source: $($BlockList.Length) entries (including comments)"
    Write-Host " Output: $($OutHash.host.keys.count) entries"
    Write-Host " RunTime: $($RunTime.TotalSeconds) seconds"

    return $OutHash 

}

# Attempt to build array out of selected source
# Output need to be caught or bad times be had
if (-not[string]::IsNullOrEmpty($BlockListURL)) {
    RegexMagic -BlockList ((Invoke-WebRequest $BlockListURL -UseBasicParsing).Content -split '\r?\n')
} 
elseif (-not[string]::IsNullOrEmpty($BlockListTXT)) {
    RegexMagic -BlockList (Get-StreamReaderArray -Path $BlockListTXT)
} 