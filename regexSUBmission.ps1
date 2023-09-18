<#
.DESCRIPTION
    --------- DISCLAIMER ---------
            Might not work 
    ------------W--I--P-----------
    Input a blocklist to view statistics and consolidate domains
        - (OPT)Output
            - hashtable: hashtable with all information (exported as .json: 200k domains ~100MB)
            - psobject: with consolidated unique SLDTLD (everything above subdomain) and subdomain count

.PARAMETER BlockListURL
    Fetch list from the world wide web

.PARAMETER BlockListTXT
    Read local file

.PARAMETER BlockListOBJ
    Read variable if it's an array - also accepts input like: -BlockListOBJ 'example.com'

.PARAMETER ConsolidateLimit
    Configure total subdomains a unique SLD+TLD match should have to be considered for consolidation
    If <example.com> has 5 found subdomains setting this to 4 will not include it in the psobject output - unless OutConsolidated is $true

.PARAMETER OutputAs
    Select what to return after ran.
        info (always): shows breakdwon of statistics regardless of other options
        hashtable (opt): hashtable which can be exported as .json 
        psobject (opt): can be exported to shorter list with wildcards

.PARAMETER OutConsolidated
    When combined with OutputAs:psobject - return the original output consolidated and wildcard those within ConsolidateLimit

.PARAMETER ExtremeDebug
    Produces ghetto-matrix-style output for troubleshooting, 
        - CTRL+F "EXTREMEDEBUG" and uncomment to write everything to a CSV. Sluggish AF.
    
.PARAMETER OutSkipped
    View skipped entries in terminal, they fly by

.NOTES
    Author: returaxel
    Version: 1.0.8
    Updated: Actually seems to give output that respects the original list.

.EXAMPLE
    Show list information, optionally use -ConsolidateLimit <X> to lower or raise consolidation limit
        .\regexSUBmission.ps1 -BlockListURL <Your favourite blocklist>

    Multiple lists is asking for trouble but almost functions. Heres how!
        $EatTheOutput = [array]$urls | % {
        .\regexSUBmission.ps1 $_ -BlockListURL $_}
#>

[CmdletBinding(DefaultParametersetName='One')] 
param (
    [Parameter(ParameterSetName='One')][string]$BlockListURL,
    [Parameter(ParameterSetName='Two')][string]$BlockListTXT,
    [Parameter(ParameterSetName='Three')][array]$BlockListOBJ,
    [ValidateSet('info','hashtable','psobject')][string]$OutputAs = 'info',
    [Parameter()][int]$ConsolidateLimit = 5,
    [Parameter()][switch]$ExtremeDebug,
    [Parameter()][switch]$OutConsolidated,
    [Parameter()][switch]$OutSkipped

)

# ------------------------------------------ [ FUNCTIONS:START ] ------------------------------------------

function RegexSUBmission {
    # Please note this function is a cardinal sin and loop itself until a match is found.
    param (
        [Parameter()][string]$InputStr,         # String to parse
        [Parameter()][string]$Regex = '^(?>[\d.]+\ |[.*-]?)([\w*-]+)(\.?[\w.*-]+)?(\.[\w-]{2,})(.*$)',
        [Parameter()][string]$IndexOf,          # From RegexMagic to track where we are in the source
        [Parameter()][Psobject]$PrevObject,     # When resubmitting bring previous result
        [Parameter()][int]$ReSubmissions = 0,   # Prevent eternal looping if something is wrong
        [Parameter()][int]$HardLoopLimit = 50,  # If the input depth exceeds this value it's skipped (depth = sum of dots)
        [Parameter()][switch]$ExtremeDebug      # Troubleshooting switch
    )

# -------------------- [ Matching ] 

    $RexMatch = [regex]::Matches($InputStr, $Regex)

    # FullMatch
    [string]$RexFullMatch = '{0}{1}{2}' -f $RexMatch.Groups[1].Value, $RexMatch.Groups[2].Value, $RexMatch.Groups[3].Value
    # Count punctuations/depth
    [int]$InputDepth = [regex]::Matches($RexFullMatch, '\.').Count

# -------------------- [ InDepth ] 

    # Continue if match found
    if (-not[string]::IsNullOrEmpty($RexFullMatch) -and ($InputDepth -le $HardLoopLimit)) {
        # Check if match contains an SLD
        [bool]$SLD = ($RexMatch.Groups[2].Value) -as [bool]
        # ReRun limt is the total punctuations in parsed input, if reached end loop
        [int]$ReSubmissions += 1
        # Save original input depth to end loop if exceed
        [int]$DepthOfOriginal = switch ($ReSubmissions) {
            1       {  $InputDepth }
            Default { $PrevObject.InputDepth }
        }

        # START: EXTREMEDEBUG
        # Writes information to file every time it passes thru (a lot)
        if ($ExtremeDebug) { 
            #[PSCustomObject]@{
            #    IndexOf = $IndexOf
            #    OriginalDepth = $DepthOfOriginal 
            #    Input = $InputStr
            #    Depth = $InputDepth
            #    SUB = $RexMatch.Groups[1].Value
            #    SLD = $RexMatch.Groups[2].Value
            #    TLD = $RexMatch.Groups[3].Value
            #    PrevSUB = $PrevObject.SUB
            #    PrevSLD = $PrevObject.SLD
            #    PrevTLD = $PrevObject.TLD
            #    Output = ('{0}.{1}' -f "($($PrevObject.SUB))", $RexFullMatch) # (SUB) value is added to domains ending with SLD+TLD (like co.uk)
            #    "Iterations(Max)" = "$ReSubmissions($DepthOfOriginal)"
            #} | Export-Csv D:\BlackLists_Test\RegexResult_new.csv -NoTypeInformation -Append
        } # END: EXTREMEDEBUG

        <# WHITELIST 
        Domains ending with SLD+TLD (example: ".co.uk"), will be consolidated under ".co.uk" unless whitelisted
        Add new by piping another one to the list below: example '\.co\.uk$|<new value>$' #>
        if (([regex]::Match($RexFullMatch,'\.co\.uk$').Success) -and ($InputDepth -le 2)) {

            # Output: whitelist match
            return [PSCustomObject]@{
                SUB = $PrevObject.SUB
                SLD = '.{0}' -f $RexMatch.Groups[1].Value
                TLD = '{0}{1}' -f $RexMatch.Groups[2].Value, $RexMatch.Groups[3].Value
                FULL = '{0}.{1}{2}{3}' -f $PrevObject.SUB, $RexMatch.Groups[1].Value, $RexMatch.Groups[2].Value, $RexMatch.Groups[3].Value
                REGX = $ReSubmissions
            }

        } # Return when input depth is 2 or no SLD match is present (does not catch whitelist) 
        elseif (($InputDepth -le 2) -or ((-not$SLD) -and (-not[string]::IsNullOrEmpty($PrevObject.SLD)))) {

            # DEBUG
            if (($ExtremeDebug)-or ($ReSubmissions -gt 10)) {
                Write-Host "Match_In: $ReSubmissions |" -NoNewline -ForegroundColor DarkGreen
                Write-Host "`t@$IndexOf`t|`t $InputStr" -ForegroundColor DarkGray
            }

            # Output: regular match
            return [PSCustomObject]@{
                SUB = $RexMatch.Groups[1].Value
                SLD = $RexMatch.Groups[2].Value
                TLD = $RexMatch.Groups[3].Value
                FULL = $RexFullMatch
                REGX = $ReSubmissions
            }
        } 

# -------------------- [ Looping ] 
        # Stop looping when SLD:$false or reached total input depth (-2)
        if ((-not$SLD) -or ($ReSubmissions -eq $PrevObject.InputDepth)) {      

            # DEBUG
            Write-Host "WarnLoop:$ReSubmissions/$($InputDepth)|" -NoNewline -ForegroundColor Red
            Write-Host "`t@$IndexOf`t|`t $InputStr | Return:NULL" -ForegroundColor DarkGray
            
            if ($ExtremeDebug) {
                $PrevObject | Out-Host
                [Console]::ReadKey() | Out-Null # Pauses until a key is pressed
            }

            return $null
        }
        else {

            # Values to bring into next iteration
            [string]$RexString = switch ($SLD) {
                $true { '{0}{1}' -f $RexMatch.Groups[2].Value,$RexMatch.Groups[3].Value }
                $false { '{0}{1}' -f $RexMatch.Groups[1].Value,$RexMatch.Groups[3].Value }
            }

            # DEBUG
            if (($ExtremeDebug) -or (($ReSubmissions % 10) -eq 0)) {
                Write-Host "ReSUBmit: $ReSubmissions |" -NoNewline -ForegroundColor DarkCyan
                Write-Host "`t@$IndexOf`t|`t $InputStr"  -ForegroundColor DarkGray
            }

            RegexSUBmission -InputStr $RexString -IndexOf $IndexOf -ReSubmissions $ReSubmissions -ExtremeDebug:$ExtremeDebug -PrevObject ([PSCustomObject]@{
                SUB = $RexMatch.Groups[1].Value
                SLD = $RexMatch.Groups[2].Value
                TLD = $RexMatch.Groups[3].Value
                FULL = '{0}{1}{2}' -f $RexMatch.Groups[1].Value, $RexMatch.Groups[2].Value, $RexMatch.Groups[3].Value
                Input = $InputStr
                InputDepth = $DepthOfOriginal
            })
        } 

    }             
    else {
        # Didn't match regex
        Write-Host "DepthErr:    |" -NoNewline -ForegroundColor DarkMagenta
        Write-Host "`t@$IndexOf`t|`t Return:NULL | $InputStr " -ForegroundColor DarkGray
        return $null
    }
}

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
        Write-Host "Error:StreamReader: " -NoNewline -ForegroundColor Red
        Write-Host $PSItem.Exception.Message -ForegroundColor Yellow
        Break
    }

    while ($null -ne ($Line = $StreamReader.ReadLine())) {
        $GenericList.Add($Line)
    }

    $StreamReader.Dispose()
    return $GenericList.ToArray()
}

function RegexMagic {
    param (
        [Parameter()][array]$BlockList,
        [ValidateSet('info','hashtable','psobject')][string]$OutputAs = 'info',
        [Parameter()][int]$ConsolidateLimit = 5,
        [Parameter()][switch]$OutConsolidated,
        [Parameter()][switch]$ExtremeDebug,
        [Parameter()][switch]$OutSkipped
    ) 

    # Hashtable
    $HashTable = @{
        Info = [ordered]@{} # Operational info 
        Domains = [ordered]@{} # Domain list
    }

# Measure full duration
$RunTime = Measure-Command { 

    # Count things
    [int]$IndexOf = 0
    [int]$Comments = 0
    [int]$Duplicate = 0

    # Start working your way thru the list
    foreach ($line in $BlockList) {

        # Tracking where we are, should correspond with source, write info to show progress
        $IndexOf += 1
        if ((($IndexOf % 10000) -eq 0)) {
            Write-Host "Index_Of:     `t@$IndexOf"-ForegroundColor DarkGray
        }

        # Skip empty and commented lines, edit regex as needed
        if (-not[string]::IsNullOrWhiteSpace($line) -and (-not[regex]::Match($line,'^!|@|#').Success)) {

            # Regex function
            try {
                $RegexMatch = RegexSUBmission -InputStr $line -IndexOf $IndexOf -ExtremeDebug:$ExtremeDebug
            }
            catch {
                Write-Host "CatchRex:   |" -NoNewline -ForegroundColor Cyan
                Write-Host "`t@$IndexOf`t|`t $line" -ForegroundColor DarkGray
            }

            # Continue if match
            if (-not[string]::IsNullOrEmpty($RegexMatch.TLD)) {
                
# Measure each iteration, added to the next one because of reasons
$RegexOperation = Measure-Command {

                $CheckSLD = $RegexMatch.SLD -as [bool]

                $RegexSLDTLD = switch ($CheckSLD) {
                    $true { '{0}{1}' -f $RegexMatch.SLD, $RegexMatch.TLD }
                    $false { '{0}{1}' -f $RegexMatch.SUB, $RegexMatch.TLD }
                }
                
                # Add if key not in hashtable
                if (-not$HashTable['Domains'][$RegexSLDTLD]) {
                    try {
                        $HashTable['Domains'][$RegexSLDTLD] = [ordered]@{
                            # Add to hashtable
                            SUB = [ordered]@{} # Sub domain
                            SLD = [string]$RegexMatch.SLD # Second level domains - everything between SUB and TLD
                            TLD = [string]$RegexMatch.TLD # Top level domain
                            FullMatch = [string]$RegexMatch.FULL
                            WellFormed = [Uri]::IsWellFormedUriString(([string]$RegexMatch.FULL), 'Relative')
                            ReSUBmissions = $RegexMatch.REGX # Times regexSUBmission ran before finishing
                            RunTimeMS = $null # Time to run this iteration
                            SrcIndex = $IndexOf
                        }
                        # Add SUB if CheckSLD:$true
                        if (-not[string]::IsNullOrEmpty($RegexMatch.SUB) -and ($CheckSLD)) {
                            $HashTable['Domains'][$RegexSLDTLD]['SUB'].Add($RegexMatch.SUB, $IndexOf)
                        }
                    }
                    catch {
                        #Write-Host  $PSItem.Exception.Message -ForegroundColor Red
                        Write-Host "ErrorNew:   |" -ForegroundColor Yellow
                        Write-Host "`t@$IndexOf`t|`t $line" -ForegroundColor DarkGray
                    }                   
            } # Add subdomain to parent in hashtable - skip if there is no subdomain
            elseif (($CheckSLD) -and -not($HashTable['Domains'][$RegexSLDTLD]['SUB']["$($RegexMatch.SUB)"])) {
                try {
                    $HashTable['Domains'][$RegexSLDTLD]['SUB'].Add($RegexMatch.SUB, $IndexOf)
                }
                catch {
                    Write-Host "ErrorAdd:    |" -NoNewline -ForegroundColor DarkYellow
                    Write-Host "`t@$IndexOf`t|`t $line" -ForegroundColor DarkGray
                }
            } 
            else { 
                # End up here if there is no subdomain and parent is already in hashtable
                $Duplicate += 1
                # Write-Host "ErrorDupe: " -NoNewline -ForegroundColor DarkYellow
                # Write-Host "@$IndexOf | ReSubmitted[$($RegexMatch.REGX)] | $line" -ForegroundColor DarkGray
            }

} # END MEASURE RunTimeMS

            # Add time to run for iteration
            if (-not[string]::IsNullOrEmpty($RegexSLDTLD)) {
                $HashTable['Domains'][$RegexSLDTLD].RunTimeMS = $RegexOperation.TotalMilliseconds
            }
        } 

        } # Output skipped entries / comments
        else {
            $Comments +=1
            if ($OutSkipped) {
                Write-Host $line -ForegroundColor DarkGray
            }
        }
    }

} # END MEASURE full duration

# --------------[ INFORMATION ] 

    # ConsolidateLimit sets the subdomain limit for a unique SLD+TLD match
    Write-Host "`n`nWorking on statistics..." -NoNewline -ForegroundColor DarkCyan
    $Consolidated = [System.Collections.Generic.List[PSObject]]@()
    foreach ($domain in $HashTable['Domains'].Keys) {
        [int]$SubKeyCount = $HashTable['Domains'][$domain]['SUB'].Keys.Count
        # If subdomain count -GE ConsolidateLimit: add SLD+TLD and the total subdomains for each to an object
        if ($SubKeyCount -ge $ConsolidateLimit) {
            $Consolidated.Add([PSCustomObject]@{Domain = ('*{0}' -f $domain) ; SubKeyCount = $SubKeyCount})
        } # If OutConsolidated:$true: add every other domain and each subdomain to the output as a separate line
        elseif (($SubKeyCount -lt $ConsolidateLimit) -and $OutConsolidated) {
            $SubKeys = $HashTable['Domains'][$domain]['SUB'].Keys
            foreach ($key in $SubKeys) {
                $Consolidated.Add([PSCustomObject]@{Domain = ('{0}{1}' -f [string]$key, $domain) ; SubKeyCount = $SubKeyCount})
            }
        }
    }
    Write-Host "DONE!" -ForegroundColor DarkGreen
    $OutStatistics = ($Consolidated.SubKeyCount -ge $ConsolidateLimit) | Measure-Object -Minimum -Maximum -Sum -Average

# Information and statistics in the hashtable
    $HashTable['Info'] = [ordered]@{
        Source = "$([int]$BlockList.Length) entries" # Total length of list
        Output = "$([int]$HashTable['Domains'].keys.count) entries excl. consolidated subdomains" # unique SLD+TLD matches
        Reoccuring = "$($OutStatistics.Count) sum of SLD+TLD matches with more than $($ConsolidateLimit) subdomains" # matched SLD+TLD
        Consolidated = "$([int]$OutStatistics.Sum) sum of subdomains for reoccuring SLD+TLD" # subdomain / hosts that have common SLD+TLD parents
        Breakdown = $OutStatistics  # Further breakdown of reoccuring / consolidated
        Iterations = $IndexOf # Sum of iterations should equal list length
        Comments = $Comments # Sum of comments in list
        Duplicate = $Duplicate # Sum of domains that were duplicated (already added once, if they had unique subdomains they are in $Consolidated)
        RunTime = "$($RunTime.TotalSeconds) seconds"
    }

# Output
    Write-Host "`n`n`t`t SUMMARY`n##############################################`n" -ForegroundColor DarkCyan
    Write-Host "Read comments for more information" -ForegroundColor DarkGray
    $HashTable['Info'] | ConvertTo-Json -Depth 3 | Out-Host
    Write-Host "##############################################" -ForegroundColor DarkCyan

    switch ($OutputAs) {
        hashtable   { $HashTable }
        psobject    { $Consolidated }
        default     { Write-Host "Default output: information"}
        }

# Cleanup
    Remove-Variable HashTable, OutStatistics, Consolidated
}

# ------------------------------------------ [ SCRIPT: CALL FUNCTION ] ------------------------------------------
# Makes an array of input (or throw error) and send it thru RegexMagic

if (-not[string]::IsNullOrEmpty($BlockListURL)) {
    RegexMagic -BlockList ((Invoke-RestMethod $BlockListURL -Method GET) -split '\r?\n')-OutputAs $OutputAs -ConsolidateLimit $ConsolidateLimit -OutConsolidated:$OutConsolidated -ExtremeDebug:$ExtremeDebug 
}
elseif (-not[string]::IsNullOrEmpty($BlockListTXT)) {
    RegexMagic -BlockList (Get-StreamReaderArray -Path $BlockListTXT) -OutputAs $OutputAs -ConsolidateLimit $ConsolidateLimit -OutConsolidated:$OutConsolidated -ExtremeDebug:$ExtremeDebug 
}
elseif ($BlockListOBJ -is [array]) {
    RegexMagic -BlockList $BlockListOBJ -OutputAs $OutputAs -ConsolidateLimit $ConsolidateLimit -OutConsolidated:$OutConsolidated -ExtremeDebug:$ExtremeDebug 
}
