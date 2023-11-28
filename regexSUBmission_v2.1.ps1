param (
    [Parameter(Mandatory=$true)][string]$BlockList,
    [ValidateSet('hashtable','psobject')][string]$OutputAs
)

# ------------------------------[ FUNCTIONS ]------------------------------
# Make funny text
function TerminalBloatifier {
    param (
        [Parameter()][string]$ThisPart,
        [Parameter()][string]$InputStr,
        [Parameter()][int]$IndexOf,
        [ValidateSet('DarkGreen','DarkCyan','Blue','DarkYellow','Cyan','White','DarkGray')][string]$Colour
    )
    Write-Host "$($ThisPart):" -NoNewline -ForegroundColor $Colour
    Write-Host " @$IndexOf`t| $InputStr " -ForegroundColor DarkGray
}

# Makes an array of text files
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
        break
    }

    while ($null -ne ($Line = $StreamReader.ReadLine())) {
        $GenericList.Add($Line)
    }

    $StreamReader.Dispose()
    return $GenericList.ToArray()
}

# Regex to find a domain in array of strings, no promises tho
function RegexSUBmission {
    param (
        [Parameter()][string]$inputStr,
        [Parameter()][string]$regex = '(?![\d.]+\ )([\w*-]+)(\.[\w.*-]+)?(\.[\w-]{2,})(.*$)'

    )

if (-not[string]::IsNullOrEmpty($InputStr) -and (-not[regex]::Match($InputStr,'^[!|@#<]').Success)) {

    [regex]::Matches($inputStr, $Regex)
    }
}

function HashTableGiver {
    param (
        [Parameter()]$RegexMatch,
        [Parameter()][hashtable]$Whitelist,
        [Parameter()][int]$IndexOf
    )

    $RegexString = $RegexMatch.Groups[1..3].Value -Join ''

    # Return hashtable
    $HashTableGift = [ordered]@{
        SUB = $RegexMatch.Groups[1].Value
        SLD = $null
        TLD = $null
        #Depth = [regex]::Matches($RegexMatch, '\.').Count
        #IndexOf = $IndexOf
    }

    # Missing SLD
    if (-not$RegexMatch.Groups[2].Success) {
        $HashTableGift['TLD'] = $RegexString
        $HashTableGift['SLD'] = $RegexMatch.Groups[1].Value
        $HashTableGift['SUB'] = $null
        #TerminalBloatifier HashGift $RegexString $IndexOf White
        return $HashTableGift
    }
    else {
        try {
            # TLD (+first SLD)
            $HashTableGift['TLD'] = [regex]::Matches($RegexString,"(\.?[\w-]*$($RegexMatch.Groups[3].Value))$").Groups[1].Value
    
            # SLD (-last SLD)
            $HashTableGift['SLD'] = ([regex]::Matches($RegexString,"(?>$($RegexMatch.Groups[1].Value))([\w.-]*)$($HashTableGift['TLD'])$").Groups[1].Value).TrimStart('.')
    
            #TerminalBloatifier HashGift $OnlySecond $IndexOf DarkGray

        }
        catch {
            Write-Host "HashGift:" -NoNewline -ForegroundColor DarkYellow
            Write-Host " @$IndexOf`t| $RegexString " -NoNewline -ForegroundColor DarkGray
            Write-Host : $PSItem.Exception.Message -ForegroundColor Yellow
        }
    }
    return $HashTableGift 
}

function ListDestroyer {
    param (
        [Parameter()][array]$BlockList,
        [ValidateSet('info','hashtable','psobject')][string]$OutputAs ='info'
    ) 

    # Hashtable
    $HashTable = @{
        Info = [ordered]@{}
        Domains = @{} # Domain list
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

            try {
                if (-not$HashTable['Domains'][$GivenHashTable['TLD']]) {
                    # Add new but with extra steps for extra fun
                    $HashTable['Domains'][$GivenHashTable['TLD']] = @{ 
                        TLD = $GivenHashTable['TLD']
                        SLD =  @{ $GivenHashTable['SLD'] = [System.Collections.Generic.List[string]]@($GivenHashTable['SUB'])}
                    }
                    #TerminalBloatifier AddedNEW $line $IndexOf DarkGreen
                } 
                elseif ($GivenHashTable['SLD'] -notin $HashTable['Domains'][$GivenHashTable['TLD']]['SLD'].Keys) { #-not$HashTable['Domains'][$GivenHashTable['TLD']]['SLD'][$GivenHashTable['SLD']] # Alternative?
                
                    # Add new SLD
                    $HashTable['Domains'][$GivenHashTable['TLD']]['SLD'][$GivenHashTable['SLD']] =  [System.Collections.Generic.List[string]]@($GivenHashTable['SUB'])
                    #TerminalBloatifier AddedSLD $line $IndexOf Cyan
                } 
                else {
                    # Add SUB to SLD
                    $HashTable['Domains'][$GivenHashTable['TLD']]['SLD'][$GivenHashTable['SLD']].Add($GivenHashTable['SUB'])
                    #TerminalBloatifier AddedSLD $line $IndexOf DarkCyan
                }
            }
            catch {
                #TerminalBloatifier AddedSLD $line $IndexOf Yellow
                #Write-Host : $PSItem.Exception.Message -ForegroundColor Yellow
            }
        }
    }

# --------------[ INFORMATION:ListDestroyer ] 

    # Quik maf
    Write-Host "`n`nWorking on statistics..." -NoNewline -ForegroundColor DarkCyan
    $Consolidated = [System.Collections.Generic.List[PSObject]]@()

    # Dig into each top(+first second level) domain
    foreach ($domain in $HashTable['Domains'].Keys) {

    # Dig into each sld and count each keys' arrays
    [int]$SldCount = $HashTable['Domains'][$domain]['SLD'].Keys.Count
    [int]$SubCount = 0

    $HashTable['Domains'][$domain]['SLD'].Keys | % {
        $SubCount += $HashTable['Domains'][$domain]['SLD'][$_].Count
        }

        $Consolidated.Add([PSCustomObject]@{Domain = $domain ; SldTotal = $SldCount ; SubTotal = $SubCount})
    }

    Write-Host "DONE!" -ForegroundColor DarkGreen
    $OutStatistics = $Consolidated.SubTotal | Measure-Object -Minimum -Maximum -Sum -Average

# Information and statistics in the hashtable
    $HashTable['Info'] = [ordered]@{
        Source = "$([int]$BlockList.Length) entries" # Total lines in source
        Output = "$([int]$HashTable['Domains'].Keys.Count) unique tld" # Total domains in output list
        Consolidated = "$([int]$OutStatistics.Sum) sum of subdomains for reoccuring" # Total subdomains for reoccuring
        Breakdown = $OutStatistics  # Further breakdown of reoccuring / consolidated
        Iterations = $IndexOf # Tracks every step of the source list and ties to the matches for easier troubleshooting
    }

# Output
    Write-Host "`n`n`t`t SUMMARY`n##############################################`n" -ForegroundColor DarkCyan

    $HashTable['Info'] | ConvertTo-Json -Depth 3 | Out-Host

    Write-Host "`nTOP FIVE" -ForegroundColor Cyan
    $Consolidated | where SldTotal -ge 100 | sort -Descending -Property SldTotal | select -Index 0,1,2,3,4,5  | Format-Table -AutoSize -Wrap | Out-Host

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
        '^https:\/\/' { ListDestroyer -BlockList ((Invoke-RestMethod $BlockList -Method GET) -split '\r?\n') -OutputAs $OutputAs}
        '^[\w]:\\'    { ListDestroyer -BlockList (Get-StreamReaderArray -Path $BlockList ) -OutputAs $OutputAs }
        default       { ListDestroyer -BlockList $BlockList -OutputAs $OutputAs}
    }
}
catch {
    Write-Error $PSItem.Exception.Message
}