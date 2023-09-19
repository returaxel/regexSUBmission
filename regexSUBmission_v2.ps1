param (
    [Parameter(Mandatory=$true)][string]$BlockList,
    [ValidateSet('hashtable','psobject')][string]$OutputAs,
    [Parameter()][int]$ConsolidateLimit = 5,
    [Parameter()][switch]$OutConsolidated
)

# ------------------------------[ FUNCTIONS ]------------------------------
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


function RegexSUBmission {
    param (
        [Parameter()][string]$InputStr,
        [Parameter()][string]$Regex = '(?![\d.]+\ )([\w*-]+)(\.[\w.*-]+)?(\.[\w-]{2,})(.*$)'
    )

# -------------------- [ Matching ] 

if (-not[string]::IsNullOrWhiteSpace($InputStr) -and (-not[regex]::Match($InputStr,'^[!|@#<]').Success)) {

    return [regex]::Matches($InputStr, $Regex)
    }
    else {
        return $null
        #Write-Host "Comment:" -NoNewline -ForegroundColor Magenta
        #Write-Host " @$IndexOf`t| $InputStr" -ForegroundColor DarkGray
    }
}

function HashTableGiver {
    param (
        [Parameter()]$RegexMatch,
        [Parameter()][hashtable]$Whitelist,
        [Parameter()][int]$IndexOf
    )

    # Return hashtable
    $HashTableGift = [ordered]@{
        SUB = [ordered]@{
            $RegexMatch.Groups[1].Value = $IndexOf
        }
        SLD = $RegexMatch.Groups[2].Value
        TLD = $RegexMatch.Groups[3].Value
        KEY = $null
        Depth = [regex]::Matches($RexFullMatch, '\.').Count
        Whitelist = $false
        IndexTracker = $IndexOf
    }

    [bool]$MatchSLD = $RegexMatch.Groups[2].Success

    if ($MatchSLD) {
        $SLDTLD = '{0}{1}' -f $RegexMatch.Groups[2].Value.Substring($RegexMatch.Groups[2].Value.LastIndexOf('.')), $RegexMatch.Groups[3].Value

        if ($Whitelist[$SLDTLD]) {
            $HashTableGift['Whitelist'] = $true
            try {
                $RegexMatch.Value.Substring($RegexMatch.Value.TrimEnd($SLDTLD).LastIndexof('.'))
            }
            catch {
                $HashTableGift['KEY'] = $SLDTLD 
            }
                    
        }
        else {
            $HashTableGift['KEY'] = $SLDTLD 
        }
    } 
    else {
        $HashTableGift['KEY'] = $RegexMatch.Value 
    }

    return $HashTableGift
}

function ListDestroyer {
    param (
        [Parameter()][array]$BlockList
    ) 

    # Hashtable
    $HashTable = @{
        Info = [ordered]@{
            Source = "$([int]$BlockList.Length) entries" 
            Output = 0
            Reoccuring = 0
            Consolidated = 0
            Breakdown = @{}
            Iterations = 0
        }
        Domains = [ordered]@{} # Domain list
        Whitelist = @{
            '.co.uk' = 2
        }
    }

    # Count things
    [int]$IndexOf = 0

    # Start working your way thru the list
    foreach ($line in $BlockList) {

        # Tracking where we are, should correspond with source, write info to show progress
        $IndexOf += 1
        if ((($IndexOf % 10000) -eq 0)) {
            Write-Host "Index_Of: @$IndexOf"-ForegroundColor DarkGray
        }

        $RegexMatch = RegexSUBmission -InputStr $line

        if (-not[string]::IsNullOrEmpty($RegexMatch)) {    

            $GivenHashTable = HashTableGiver $RegexMatch $HashTable['WhiteList'] $IndexOf 

            #Write-Host "OutDebug:" -NoNewline -ForegroundColor DarkYellow
            #Write-Host " @$IndexOf`t| $($GivenHashTable['KEY']) | $line" -ForegroundColor DarkGray
            #$GivenHashTable | ConvertTo-Json | Out-Host

            try {
                if (-not$HashTable['Domains'][$GivenHashTable['KEY']]) {
                    # Add new 
                    $HashTable['Domains'][$GivenHashTable['KEY']] = $GivenHashTable
                } 
                else {
                    # Add subkey to existing
                    $HashTable['Domains'][$GivenHashTable['KEY']]['SUB'].Add($GivenHashTable['SUB'], $IndexOf)
                }
            }
            catch {
                #Write-Host "NotAdded:" -NoNewline -ForegroundColor DarkYellow
                #Write-Host " @$IndexOf`t| $($GivenHashTable['KEY']) | $line" -ForegroundColor DarkGray
                #$GivenHashTable | ConvertTo-Json -Depth 3 | Out-Host
                #Start-Sleep 1
            }

        }
    }
    $HashTable['Info']['Iterations'] = $IndexOf 
    return $HashTable
}

function StatisticallySpeaking {
    param(
        [ValidateSet('info','hashtable','psobject')][string]$OutputAs,
        [Parameter()][hashtable]$EatenHashTable,
        [Parameter()][switch]$OutConsolidated,
        [Parameter()][int]$ConsolidateLimit = 5
    )
# --------------[ INFORMATION ] 

    # ConsolidateLimit sets the subdomain limit for a unique SLD+TLD match
    Write-Host "`n`nWorking on statistics..." -NoNewline -ForegroundColor DarkCyan
    $Consolidated = [System.Collections.Generic.List[PSObject]]@()
    foreach ($domain in $EatenHashTable['Domains'].Keys) {
        [int]$SubKeyCount = $EatenHashTable['Domains'][$domain]['SUB'].Keys.Count
        # If subdomain count -GE ConsolidateLimit: add SLD+TLD and the total subdomains for each to an object
        if ($SubKeyCount -ge $ConsolidateLimit) {
            $Consolidated.Add([PSCustomObject]@{Domain = ('*{0}' -f $domain) ; SubKeyCount = $SubKeyCount})
        } # If OutConsolidated:$true: output everything 
        elseif (($SubKeyCount -lt $ConsolidateLimit) -and $OutConsolidated) {
            $SubKeys = $EatenHashTable['Domains'][$domain]['SUB'].Keys
            foreach ($key in $SubKeys) {
                $Consolidated.Add([PSCustomObject]@{Domain = ('{0}{1}' -f [string]$key, $domain) ; SubKeyCount = $SubKeyCount})
            }
        }
    }
    Write-Host "DONE!" -ForegroundColor DarkGreen
    $OutStatistics = ($Consolidated.SubKeyCount -ge $ConsolidateLimit) | Measure-Object -Minimum -Maximum -Sum -Average
    
    # Information and statistics in the hashtable
    $EatenHashTable['Info']['Output'] = "$([int]$EatenHashTable['Domains'].Keys.Count) entries" 
    $EatenHashTable['Info']['Reoccuring'] = "$($OutStatistics.Count) had more than $($ConsolidateLimit) subdomains" 
    $EatenHashTable['Info']['Consolidated'] = "$([int]$OutStatistics.Sum) sum of subdomains for reoccuring" 
    $EatenHashTable['Info']['Breakdown'] = $OutStatistics  
  
    # Output
    Write-Host "`n`n`t`t SUMMARY`n##############################################`n" -ForegroundColor DarkCyan
    $EatenHashTable['Info'] | ConvertTo-Json -Depth 3 | Out-Host
    Write-Host "##############################################" -ForegroundColor DarkCyan

    switch ($OutputAs) {
    hashtable   { return $EatenHashTable }
    psobject    { return $Consolidated }
    }
}

# ------------------------------[ SCRIPT:RUN ]------------------------------

[hashtable]$EatTheOutput = switch -regex ($BlockList) {
    '(^https:\/\/)' { ListDestroyer -BlockList (Invoke-RestMethod $BlockList -Method GET) }
    '(^[\w]:\\)'    { ListDestroyer -BlockList (Get-StreamReaderArray -Path $BlockList ) }
    default         { ListDestroyer -BlockList $BlockList }
}

$EatTheOutput |Out-Host

StatisticallySpeaking -OutputAs $OutputAs -EatenHashTable $EatTheOutput -OutConsolidated:$OutConsolidated -ConsolidateLimit $ConsolidateLimit