<#
.SYNOPSIS
    M365 Public Analyzer (OSINT) – analyzes public Microsoft 365 signals for a domain.

.DESCRIPTION
    No authentication required. Collects and reports on:
      - DNS controls: MX, SPF, DMARC, DKIM (guessed), MTA-STS (TXT + policy)
      - Microsoft identity realm: tenant ID (via OpenID metadata), realm (managed/federated), IdP brand
      - Skype/Teams SRV and Autodiscover presence
      - Outlook/OWA public endpoints sanity checks
    Outputs a structured JSON file and (optionally) a Markdown report.

.PARAMETER Domain
    Target primary email/web domain (e.g., contoso.com).

.PARAMETER OutJson
    Path to write JSON results (default: .\m365_public_analyzer.<domain>.json)

.PARAMETER OutMarkdown
    Optional path to write a Markdown report.

.PARAMETER TimeoutSec
    HTTP/DNS timeout (seconds). Default: 10

.EXAMPLE
    .\m365_public_analyzer.ps1 -Domain contoso.com -OutMarkdown .\contoso.md

.EXAMPLE
    .\m365_public_analyzer.ps1 -Domain fabrikam.io

.NOTES
    Author: Your Name (GitHub @da13m)
    License: MIT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Domain,

    [string]$OutJson = $(Join-Path -Path (Get-Location) -ChildPath ("m365_public_analyzer.{0}.json" -f $Domain)),

    [string]$OutMarkdown,

    [int]$TimeoutSec = 10
)

# -------------------------
# Helpers
# -------------------------
function New-HttpClient {
    param([int]$TimeoutSec = 10)
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $true
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd("m365-public-analyzer/1.0 (+https://github.com/da13m)")
    return $client
}

function Invoke-HttpGet {
    param(
        [System.Net.Http.HttpClient]$Client,
        [string]$Url
    )
    try {
        $resp = $Client.GetAsync($Url).GetAwaiter().GetResult()
        $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return [PSCustomObject]@{
            Url = $Url
            StatusCode = [int]$resp.StatusCode
            Headers = $resp.Headers + $resp.Content.Headers
            Body = $body
            Error = $null
        }
    } catch {
        return [PSCustomObject]@{
            Url = $Url
            StatusCode = $null
            Headers = @{}
            Body = $null
            Error = $_.Exception.Message
        }
    }
}

function Resolve-DnsRecords {
    param(
        [string]$Name,
        [ValidateSet('MX','TXT','CNAME','SRV')]
        [string]$Type
    )
    try {
        switch ($Type) {
            'MX'   { return (Resolve-DnsName -Name $Name -Type MX   -ErrorAction Stop) }
            'TXT'  { return (Resolve-DnsName -Name $Name -Type TXT  -ErrorAction Stop) }
            'CNAME'{ return (Resolve-DnsName -Name $Name -Type CNAME -ErrorAction Stop) }
            'SRV'  { return (Resolve-DnsName -Name $Name -Type SRV  -ErrorAction Stop) }
        }
    } catch {
        return @()
    }
}

function New-Finding {
    param(
        [string]$Category,
        [string]$Title,
        [string]$Risk = 'info', # info | low | medium | high | critical
        [string]$Detail,
        [hashtable]$Data
    )
    return [PSCustomObject]@{
        category = $Category
        title    = $Title
        risk     = $Risk
        detail   = $Detail
        data     = $Data
    }
}

# -------------------------
# Begin analysis
# -------------------------
$client = New-HttpClient -TimeoutSec $TimeoutSec
$findings = New-Object System.Collections.Generic.List[object]
$now = (Get-Date).ToUniversalTime().ToString("o")

# 1) MX
$mx = Resolve-DnsRecords -Name $Domain -Type MX
$mxHosts = @()
if ($mx) {
    $mxHosts = $mx | Sort-Object -Property { $_.QueryType } | ForEach-Object { $_.Exchange }
    $findings.Add((New-Finding -Category 'Email' -Title 'MX Records' -Risk 'info' -Detail "Found MX records." -Data @{mx=$mxHosts}))
} else {
    $findings.Add((New-Finding -Category 'Email' -Title 'MX Records Missing' -Risk 'high' -Detail "No MX records returned." -Data @{}))
}

# 2) SPF
$spfTxt = Resolve-DnsRecords -Name $Domain -Type TXT | Where-Object { $_.Strings -match '^v=spf1' }
if ($spfTxt) {
    $spf = ($spfTxt.Strings -join ' ')
    $risk = if ($spf -match '\s-all') {'info'} elseif ($spf -match '\~all') {'low'} else {'medium'}
    $findings.Add((New-Finding -Category 'Email' -Title 'SPF Policy' -Risk $risk -Detail "SPF record detected." -Data @{spf=$spf}))
} else {
    $findings.Add((New-Finding -Category 'Email' -Title 'SPF Missing' -Risk 'medium' -Detail "No SPF record found." -Data @{}))
}

# 3) DMARC
$dmarcTxt = Resolve-DnsRecords -Name ("_dmarc.{0}" -f $Domain) -Type TXT | Where-Object { $_.Strings -match '^v=DMARC1' }
if ($dmarcTxt) {
    $dmarc = ($dmarcTxt.Strings -join ' ')
    $polMatch = [regex]::Match($dmarc, 'p=([a-zA-Z]+)')
    $pol = if ($polMatch.Success) { $polMatch.Groups[1].Value.ToLower() } else { 'none' }
    $risk = switch ($pol) {
        'reject' { 'info' }
        'quarantine' { 'low' }
        default { 'medium' }
    }
    $findings.Add((New-Finding -Category 'Email' -Title 'DMARC Policy' -Risk $risk -Detail "DMARC record detected (p=$pol)." -Data @{dmarc=$dmarc}))
} else {
    $findings.Add((New-Finding -Category 'Email' -Title 'DMARC Missing' -Risk 'high' -Detail "No DMARC record found at _dmarc.$Domain." -Data @{}))
}

# 4) DKIM (guess common selectors)
$dkimSelectors = @('selector1','selector2','default')
$dkimHits = @()
foreach ($sel in $dkimSelectors) {
    $host = "{0}._domainkey.{1}" -f $sel, $Domain
    $rec = Resolve-DnsRecords -Name $host -Type CNAME
    if (-not $rec) { $rec = Resolve-DnsRecords -Name $host -Type TXT }
    if ($rec) {
        $dkimHits += $host
    }
}
if ($dkimHits.Count -gt 0) {
    $findings.Add((New-Finding -Category 'Email' -Title 'DKIM Present (guessed selectors)' -Risk 'info' -Detail "Found DKIM records for common selectors." -Data @{selectors=$dkimHits}))
} else {
    $findings.Add((New-Finding -Category 'Email' -Title 'DKIM Not Confirmed' -Risk 'low' -Detail "No DKIM record found for common selectors (may still exist with non-standard selector names)." -Data @{}))
}

# 5) MTA-STS (DNS + policy)
$mtaStsTxt = Resolve-DnsRecords -Name ("_mta-sts.{0}" -f $Domain) -Type TXT | Where-Object { $_.Strings -match '^v=STSv1' }
$mtaStsPolicy = $null
if ($mtaStsTxt) {
    $policyUrl = "https://mta-sts.$Domain/.well-known/mta-sts.txt"
    $resp = Invoke-HttpGet -Client $client -Url $policyUrl
    if ($resp.StatusCode -eq 200 -and $resp.Body) { $mtaStsPolicy = $resp.Body.Trim() }
    $risk = if ($mtaStsPolicy) {'info'} else {'low'}
    $findings.Add((New-Finding -Category 'Email' -Title 'MTA-STS' -Risk $risk -Detail ("TXT present. Policy fetch " + ($(if ($mtaStsPolicy) {"succeeded"} else {"failed"})) + ".") -Data @{policyUrl=$policyUrl; policy=$mtaStsPolicy}))
} else {
    $findings.Add((New-Finding -Category 'Email' -Title 'MTA-STS Missing' -Risk 'low' -Detail "No _mta-sts TXT found; TLS policy not advertised." -Data @{}))
}

# 6) Autodiscover
$autodiscover = Resolve-DnsRecords -Name ("autodiscover.{0}" -f $Domain) -Type CNAME
if ($autodiscover) {
    $findings.Add((New-Finding -Category 'Exchange' -Title 'Autodiscover CNAME' -Risk 'info' -Detail "Autodiscover CNAME present." -Data @{target=($autodiscover.CName)}))
} else {
    $findings.Add((New-Finding -Category 'Exchange' -Title 'Autodiscover Not Found' -Risk 'low' -Detail "No CNAME for autodiscover.$Domain (may still work via SRV or implicit methods)." -Data @{}))
}

# 7) Skype/Teams SRV
$srvSip = Resolve-DnsRecords -Name ("_sip._tls.{0}" -f $Domain) -Type SRV
$srvFed = Resolve-DnsRecords -Name ("_sipfederationtls._tcp.{0}" -f $Domain) -Type SRV
if ($srvSip) {
    $findings.Add((New-Finding -Category 'Teams' -Title 'SIP TLS SRV' -Risk 'info' -Detail "SRV _sip._tls present." -Data @{records=$srvSip.Target}))
} else {
    $findings.Add((New-Finding -Category 'Teams' -Title 'SIP TLS SRV Missing' -Risk 'low' -Detail "No _sip._tls SRV record found." -Data @{}))
}
if ($srvFed) {
    $findings.Add((New-Finding -Category 'Teams' -Title 'Federation SRV' -Risk 'info' -Detail "SRV _sipfederationtls._tcp present." -Data @{records=$srvFed.Target}))
} else {
    $findings.Add((New-Finding -Category 'Teams' -Title 'Federation SRV Missing' -Risk 'low' -Detail "No _sipfederationtls._tcp SRV record found." -Data @{}))
}

# 8) Tenant discovery via OpenID metadata (tenant ID)
$oidc = Invoke-HttpGet -Client $client -Url ("https://login.microsoftonline.com/{0}/v2.0/.well-known/openid-configuration" -f $Domain)
$tenantId = $null
if ($oidc.StatusCode -eq 200 -and $oidc.Body) {
    try {
        $j = $oidc.Body | ConvertFrom-Json
        # Issuer looks like https://login.microsoftonline.com/{tenantid}/v2.0
        $issuer = $j.issuer
        $tidMatch = [regex]::Match($issuer, 'https:\/\/login\.microsoftonline\.com\/([0-9a-fA-F-]{36})\/')
        if ($tidMatch.Success) { $tenantId = $tidMatch.Groups[1].Value }
        $findings.Add((New-Finding -Category 'Identity' -Title 'OpenID Configuration' -Risk 'info' -Detail "Fetched OpenID configuration; extracted tenant ID if present." -Data @{issuer=$issuer; tenantId=$tenantId}))
    } catch {
        $findings.Add((New-Finding -Category 'Identity' -Title 'OpenID Parse Error' -Risk 'low' -Detail "Could not parse OpenID configuration JSON." -Data @{error=$_.Exception.Message}))
    }
} else {
    $findings.Add((New-Finding -Category 'Identity' -Title 'OpenID Configuration Missing' -Risk 'low' -Detail "Could not retrieve OpenID metadata for domain." -Data @{status=$oidc.StatusCode; error=$oidc.Error}))
}

# 9) User realm discovery (Managed vs Federated)
$realmUrl = "https://login.microsoftonline.com/getuserrealm.srf?login=user@$Domain&json=1"
$realm = Invoke-HttpGet -Client $client -Url $realmUrl
if ($realm.StatusCode -eq 200 -and $realm.Body) {
    try {
        $rj = $realm.Body | ConvertFrom-Json
        $accountType = $rj.AccountType  # Managed | Federated
        $authUrl = $rj.FederationBrandName
        $stsAuthUrl = $rj.AuthURL
        $risk = if ($accountType -eq 'Federated') {'info'} else {'info'}
        $findings.Add((New-Finding -Category 'Identity' -Title 'User Realm' -Risk $risk -Detail "AccountType=$accountType" -Data @{accountType=$accountType; federationBrand=$authUrl; stsAuthUrl=$stsAuthUrl}))
    } catch {
        $findings.Add((New-Finding -Category 'Identity' -Title 'User Realm Parse Error' -Risk 'low' -Detail "Could not parse realm JSON." -Data @{error=$_.Exception.Message}))
    }
} else {
    $findings.Add((New-Finding -Category 'Identity' -Title 'User Realm Unavailable' -Risk 'low' -Detail "Could not retrieve user realm info." -Data @{status=$realm.StatusCode; error=$realm.Error}))
}

# 10) Outlook/OWA reachability checks (very light sanity)
$owaChecks = @(
    "https://outlook.office.com/owa/",
    "https://outlook.office365.com/owa/",
    ("https://outlook.office.com/mail/?domain={0}" -f $Domain)
)
$owaResults = @()
foreach ($u in $owaChecks) {
    $res = Invoke-HttpGet -Client $client -Url $u
    $owaResults += [PSCustomObject]@{ url=$u; status=$res.StatusCode; error=$res.Error }
}
$findings.Add((New-Finding -Category 'Exchange' -Title 'OWA Endpoints' -Risk 'info' -Detail "Public endpoints reachable status codes captured." -Data @{results=$owaResults}))

# -------------------------
# Scoring (simple heuristic)
# -------------------------
$riskWeights = @{ info=0; low=1; medium=3; high=6; critical=10 }
$totalScore = 0
foreach ($f in $findings) {
    $totalScore += $riskWeights[$f.risk]
}

$summary = [PSCustomObject]@{
    analyzedAtUtc = $now
    domain        = $Domain
    score         = $totalScore
    scoreHint     = "Higher is worse (aggregate of issue severities)."
    items         = $findings
}

# -------------------------
# Output JSON
# -------------------------
$summary | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 -FilePath $OutJson
Write-Host "[+] JSON written to $OutJson"

# -------------------------
# Optional Markdown
# -------------------------
if ($OutMarkdown) {
$md = @()
$md += "# M365 Public Analyzer (OSINT)"
$md += ""
$md += "**Domain:** `$Domain`  "
$md += "**Analyzed (UTC):** $now  "
$md += "**Risk Score:** $totalScore  "
$md += ""
$md += "## Findings"
$md += ""
foreach ($f in $findings) {
    $md += $"### { $f.category } – { $f.title }"
    $md += $"**Risk:** `{ $f.risk }`  "
    $md += $f.detail
    if ($f.data -and $f.data.Keys.Count -gt 0) {
        $md += ""
        $md += "<details><summary>Data</summary>"
        $md += ""
        $md += "```json"
        $md += ($f.data | ConvertTo-Json -Depth 6)
        $md += "```"
        $md += "</details>"
    }
    $md += ""
}
$md -join "`r`n" | Out-File -Encoding UTF8 -FilePath $OutMarkdown
Write-Host "[+] Markdown written to $OutMarkdown"
}

# Done
