[CmdletBinding(DefaultParametersetName='One')] 
param (
    [Parameter(ParameterSetName='One')][string]$BlockListURL,
    [Parameter(ParameterSetName='Two')][string]$BlockListTXT,
    [Parameter(ParameterSetName='Three')][array]$BlockListOBJ,
    [ValidateSet('info','hashtable','psobject')][string]$OutputAs = 'info',
    [Parameter()][int]$ConsolidateLimit = 5,
    [Parameter()][switch]$OutConsolidated
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
        [Parameter()][string]$Regex = '^(?>[\d.]+\ |[.*-]?)([\w*-]+)(\.?[\w.*-]+)?(\.[\w-]{2,})(.*$)'
    )

# -------------------- [ Matching ] 

if (-not[string]::IsNullOrWhiteSpace($InputStr) -and (-not[regex]::Match($InputStr,'^!|^@|^#|^<').Success)) {

    [regex]::Matches($InputStr, $Regex)

    }
    else {
        #Write-Host "No_Match:" -NoNewline -ForegroundColor Magenta
        #Write-Host "`t@$IndexOf`t|`t $InputStr" -ForegroundColor DarkGray
    }

}

function HashTableGiver {
    param (
        [Parameter()][System.Text.RegularExpressions.Group]$RegexMatch,
        [Parameter()][string]$IndexOf,
        [Parameter()][bool]$HasSLD,
        [Parameter()][hashtable]$Whitelist
    )

    # Return hashtable
    switch ($HasSLD) {
        $true  { 
            $Group2Arr = $RegexMatch.Groups[2].Value.Split('.')
            [ordered]@{
                SUB = [ordered]@{
                    $RegexMatch.Groups[1].Value = $IndexOf
                }
                SLD = $RegexMatch.Groups[2].Value.Substring($RegexMatch.Groups[2].Value.LastIndexOf('.'))
                TLD = $RegexMatch.Groups[3].Value
                Depth = $RegexMatch.Groups[2].Value.Split('.').Count
                WhiteList = $Group2Arr[($Group2Arr.Count-2)]
                IndexTracker = [int]$IndexOf
            }
        }
        $false { 
            [ordered]@{
                SUB = $RegexMatch.Groups[1].Value
                SLD = ''
                TLD = $RegexMatch.Groups[3].Value
                IndexTracker = [int]$IndexOf
            }
        }
    }
}

function StatisticallySpeaking {
    param(
        [ValidateSet('info','hashtable','psobject')][string]$OutputAs,
        [Parameter()][hashtable]$HashTable,
        [Parameter()][switch]$OutConsolidated,
        [Parameter()][int]$ConsolidateLimit = 5

    )
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
    $HashTable['Info']['Output'] = "$([int]$HashTable['Domains'].keys.count) entries excl. consolidated subdomains" 
    $HashTable['Info']['Reoccuring'] = "$($OutStatistics.Count) sum of SLD+TLD matches with more than $($ConsolidateLimit) subdomains" 
    $HashTable['Info']['Consolidated'] = "$([int]$OutStatistics.Sum) sum of subdomains for reoccuring SLD+TLD" 
    $HashTable['Info']['Breakdown'] = $OutStatistics  
  

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

function ListDestroyer {
    param (
        [Parameter()][array]$BlockList
    ) 

    # Hashtable
    $HashTable = @{
        Info = [ordered]@{
            Source = "$([int]$BlockList.Length) entries" 
            Output = $null
            Reoccuring = $null
            Consolidated = $null
            Breakdown = $null 
            Iterations = $null
            #RunTime = "$($RunTime.TotalSeconds) seconds"
        }
        Domains = [ordered]@{} # Domain list
    }

    # Count things
    [int]$IndexOf = 0

    # Start working your way thru the list
    foreach ($line in $BlockList) {

        # Tracking where we are, should correspond with source, write info to show progress
        $IndexOf += 1

        $RegexMatch = RegexSUBmission -InputStr $line

        if ($RegexMatch) {
            
            [bool]$HasSLD = $RegexMatch.Groups[2].Success

            $KeyName = switch ($HasSLD) {
                $true   { '{0}{1}' -f $RegexMatch.Groups[2].Value.Substring($RegexMatch.Groups[2].Value.LastIndexOf('.')), $RegexMatch.Groups[3].Value }
                $false { '{0}{1}' -f $RegexMatch.Groups[1].Value, $RegexMatch.Groups[3].Value  }
            }

            $GivenHashTable = HashTableGiver $RegexMatch $IndexOf $HasSLD

            if (-not$HashTable['Domains'][$KeyName]) {
                # Add new 
                $HashTable.Domains[$KeyName] = $GivenHashTable
            } 
            else {
                # Add subkey to existing
                $HashTable.Domains[$KeyName]['SUB'].Add($GivenHashTable['SUB'].Keys, $IndexOf)
            }
        }
    }
    $HashTable['Info']['Iterations'] = $IndexOf 
    return $HashTable
}

$RunTime = Measure-Command {

    $EatTheOutput = if (-not[string]::IsNullOrEmpty($BlockListURL)) {
        ListDestroyer -BlockList ((Invoke-RestMethod $BlockListURL -Method GET) -split '\r?\n')  
    }
    elseif (-not[string]::IsNullOrEmpty($BlockListTXT)) {
        ListDestroyer -BlockList (Get-StreamReaderArray -Path $BlockListTXT) 
    }
    elseif ($BlockListOBJ -is [array]) {
        ListDestroyer -BlockList $BlockListOBJ
    }
    StatisticallySpeaking -OutputAs $OutputAs -HashTable $EatTheOutput -OutConsolidated:$OutConsolidated -ConsolidateLimit $ConsolidateLimit
}

Write-Host $RunTime.TotalSeconds -ForegroundColor DarkCyan

