param (
    [Parameter(Mandatory=$true)][string]$BlockList,
    [ValidateSet('info','hashtable','psobject')][string]$OutputAs ='info',
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
        [Parameter()][array]$BlockList,
        [ValidateSet('info','hashtable','psobject')][string]$OutputAs ='info',
        [Parameter()][switch]$OutConsolidated,
        [Parameter()][int]$ConsolidateLimit = 5
    ) 

    # Hashtable
    $HashTable = @{
        Info = [ordered]@{}
        Domains = [ordered]@{} # Domain list
        Whitelist = @{
           # '.co.uk' = 2
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

# --------------[ INFORMATION:ListDestroyer ] 

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
        Source = "$([int]$BlockList.Length) entries" # Total lines in source
        Output = "$([int]$HashTable['Domains'].Keys.Count) entries" # Total domains in output list
        Reoccuring = "$($OutStatistics.Count) had more than $($ConsolidateLimit) subdomains" # Domains caught by '-ConsolidateLimit', ie they had more than set subdomains
        Consolidated = "$([int]$OutStatistics.Sum) sum of subdomains for reoccuring" # Total subdomains for reoccuring
        Breakdown = $OutStatistics  # Further breakdown of reoccuring / consolidated
        Iterations = $IndexOf # Tracks every step of the source list and ties to the matches for easier troubleshooting
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

}

# ------------------------------[ SCRIPT:RUN ]------------------------------
try {
    switch -regex ($BlockList) {
        '^https:\/\/' { ListDestroyer -BlockList ((Invoke-RestMethod $BlockList -Method GET) -split '\r?\n') -OutputAs $OutputAs -OutConsolidated:$OutConsolidated -ConsolidateLimit $ConsolidateLimit }
        '^[\w]:\\'    { ListDestroyer -BlockList (Get-StreamReaderArray -Path $BlockList ) -OutputAs $OutputAs -OutConsolidated:$OutConsolidated -ConsolidateLimit $ConsolidateLimit }
        default       { ListDestroyer -BlockList $BlockList -OutputAs $OutputAs -OutConsolidated:$OutConsolidated -ConsolidateLimit $ConsolidateLimit }
    }
}
catch {
    Write-Error $PSItem.Exception.Message
}
