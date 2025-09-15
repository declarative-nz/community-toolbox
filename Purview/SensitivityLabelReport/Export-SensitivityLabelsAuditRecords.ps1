<#
.SYNOPSIS
Exports Microsoft 365 Sensitivity Label audit records to CSV and an interactive HTML report.

.DESCRIPTION
Searches the Unified Audit Log for Sensitivity Label-related activity across
SharePoint/OneDrive, desktop Office apps, and Exchange Online (email). The
script resolves label IDs to display names and priorities, detects label
upgrades/downgrades/removals, and emits a normalized CSV report with per-event
context (user, device/app, document/site, old/new labels, and action).

.PREREQUISITES
- Connect to Exchange Online: `Connect-ExchangeOnline`
- Connect to Microsoft Purview (Security & Compliance): `Connect-IPPSSession`
- Permissions to run `Search-UnifiedAuditLog` and `Get-Label` (for example,
  View-Only Audit Logs, Compliance Administrator, or equivalent custom roles).

.OUTPUTS
- CSV file: `./SensitivityLabelsAuditRecords.csv`
  Columns: `TimeStamp, User, Target, Reason, Label, LabelId, OldLabel, OldLabelId,
  NewPriority, OldPriority, LabelAction, EventCode, Document, Location,
  SiteLabel, SiteLabelId, Device, Application, Action`.
- HTML file (interactive): `./SensitivityLabelsAuditRecords.html` with sorting, search,
  per-column filters, presets, column toggles, and theme switcher.

.PARAMETER StartDate
Start of the time window to search. Accepts a DateTime (e.g.,
`'2025-08-01'`), an integer offset in days relative to now (e.g., `-7`
means 7 days ago), or a compact relative string like `'-12h'` (12 hours ago)
or `'+3d'` (in 3 days). Also accepts keywords: `today`, `yesterday`, `now`.
Defaults to 180 days ago.

.PARAMETER EndDate
End of the time window to search. Accepts a DateTime, integer day offsets
(`0` for now, `-1` for yesterday), compact relative strings (e.g., `'-3h'`,
`'+1d'`), or keywords: `today`, `yesterday`, `now`. Defaults to now.

.PARAMETER OutputCsvFile
Path to the CSV file to write. Defaults to `./SensitivityLabelsAuditRecords.csv`.

.PARAMETER OutputHtmlFile
Path to the interactive HTML report to write. Defaults to `./SensitivityLabelsAuditRecords.html`.

.PARAMETER AddTimestamp
When set, appends a timestamp (yyyyMMdd-HHmmss) to the CSV and HTML filenames
to support historical runs in pipelines.

.PARAMETER PassThru
When set, also returns the report objects to the pipeline.

.PARAMETER OpenHtml
When set, opens the generated HTML report after creation.

.NOTES
- Default lookback: last 180 days (subject to tenant retention).
- Paging: `SessionCommand = ReturnLargeSet` (up to 5,000 per page; safety cap 50 pages).
- Classification: prefer `LabelEventType`; fallback to label priority comparison.
- Date inputs: accept DateTime, integer day offsets (e.g., `-7`), relative strings (`-12h`, `+3d`),
  and keywords (`today`, `yesterday`, `now`).
- Report order: newest first; the HTML header shows a descending sort indicator on TimeStamp.
- HTML interactions: global search, per-column filters (supports OR via `A|B`), presets, column visibility
  with saved state, theme toggle, and “Export Visible CSV”.

.EXAMPLE
# Connect to services
Connect-ExchangeOnline
Connect-IPPSSession

# Run the script and open HTML
./Export-SensitivityLabelsAuditRecords.ps1 -OpenHtml

.EXAMPLE
# Last 7 days to now, with custom path
./Export-SensitivityLabelsAuditRecords.ps1 -StartDate -7 -EndDate 0 -OutputCsvFile C:\Temp\label-audit.csv

.EXAMPLE
# Last 12 hours to now
./Export-SensitivityLabelsAuditRecords.ps1 -StartDate '-12h' -EndDate now

.EXAMPLE
# From start of yesterday to end of today (approx now)
./Export-SensitivityLabelsAuditRecords.ps1 -StartDate yesterday -EndDate today

.LINK
Search-UnifiedAuditLog: https://learn.microsoft.com/microsoft-365/compliance/audit-search
Get-Label: https://learn.microsoft.com/powershell/module/exchange/get-label
#>

#Requires -Version 7
#Requires -Modules ExchangeOnlineManagement

param(
    [Parameter()]
    [object]$StartDate = (Get-Date).AddDays(-180),

    [Parameter()]
    [object]$EndDate = (Get-Date),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputCSVFile = (Join-Path -Path (Get-Location) -ChildPath 'SensitivityLabelsAuditRecords.csv'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputHtmlFile = (Join-Path -Path (Get-Location) -ChildPath 'SensitivityLabelsAuditRecords.html'),

    [switch]$AddTimestamp,
    [switch]$PassThru
    , [switch]$OpenHtml
)

function Resolve-DateInput {
    param(
        [Parameter()] [AllowNull()] [object]$Value,
        [Parameter(Mandatory)] [DateTime]$Default
    )
    if ($null -eq $Value -or ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value))) {
        return $Default
    }
    if ($Value -is [DateTime]) { return [DateTime]$Value }
    if ($Value -is [int]) { return (Get-Date).AddDays([int]$Value) }
    if ($Value -is [string]) {
        $s = $Value.Trim()
        # Relative offset pattern: [+|-]number with optional unit (d=days, h=hours)
        $rx = [regex]::new('^([+-]?\d+)\s*([dh])?$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $m = $rx.Match($s)
        if ($m.Success) {
            $n = [int]$m.Groups[1].Value
            $u = $m.Groups[2].Value.ToLowerInvariant()
            if ($u -eq 'h') { return (Get-Date).AddHours($n) }
            else { return (Get-Date).AddDays($n) }
        }
        switch ($s.ToLowerInvariant()) {
            'today'     { return (Get-Date) }
            'yesterday' { return (Get-Date).AddDays(-1) }
            'now'       { return (Get-Date) }
        }
        $dt = [DateTime]::MinValue
        if ([DateTime]::TryParse($Value, [ref]$dt)) {
            return $dt
        }
        throw "Unable to parse date input '$Value'. Provide a DateTime, an integer day offset (e.g., -7), a compact relative (e.g., '-12h', '+3d'), or a keyword (today, yesterday, now)."
    }
    throw "Unsupported date input type: $($Value.GetType().FullName)"
}

$StartDateDt = Resolve-DateInput -Value $StartDate -Default (Get-Date).AddDays(-180)
$EndDateDt   = Resolve-DateInput -Value $EndDate   -Default (Get-Date)

# Basic validation
if ($StartDateDt -ge $EndDateDt) {
    throw "StartDate must be earlier than EndDate. Provided StartDate: $StartDateDt EndDate: $EndDateDt"
}

Clear-Host

# --- Preflight ---
# Must be connected to Exchange Online and the Microsoft Purview (SCC) endpoint.
# This check validates the Exchange Online module is present; the Purview
# connection is validated when `Get-Label` runs below.
$ModulesLoaded = Get-Module | Select-Object -ExpandProperty Name
If (!($ModulesLoaded -match "ExchangeOnlineManagement")) {
    Write-Host "Please connect to the Exchange Online Management module and then restart the script"
    return
}

# Fetch labels (for name + priority maps). Requires a Purview/SCC session.
$TenantLabels = @{}
$TenantLabelPriority = @{}
Try {
    $Labels = Get-Label
} Catch {
    Write-Host "Your PowerShell session must be connected to the Compliance endpoint to fetch label data"
    return
}
$Labels.ForEach({
    $TenantLabels[[string]$_.ImmutableId]      = $_.DisplayName
    $TenantLabelPriority[[string]$_.ImmutableId] = [int]$_.Priority
})

# --- Parameters ---
# Using StartDateDt/EndDateDt/OutputCSVFile from param block above.
Write-Host "Searching Microsoft 365 Audit Log to find audit records for sensitivity labels"

# Include both file and email operations; `SensitivityLabelUpdated` is used by email.
$Operations = @(
  "SensitivityLabeledFileOpened",
  "SensitivityLabeledFileRenamed",
  "SensitivityLabelRemoved",           # desktop/email remove
  "SensitivityLabelApplied",           # desktop/email apply
  "SensitivityLabelUpdated",           # email update (important)
  "FileSensitivityLabelApplied",
  "FileSensitivityLabelRemoved",
  "FileSensitivityLabelChanged",
  "Assign label to group."
)

# --- Helper: robust paging for large result sets ---
# Uses `SessionCommand = ReturnLargeSet` to retrieve up to 5,000 results per call,
# deduplicates by Identity, then sorts by CreationDate.
function Get-UAuditRecords {
     param(
         [datetime]$StartDate,
         [datetime]$EndDate,
         [string[]]$Operations,
         [int]$BatchSize = 5000
     )
     $sessionId = [guid]::NewGuid().ToString()
     $all   = @()
     $page  = 1
     while ($true) {
         $params = @{
             StartDate      = $StartDate
             EndDate        = $EndDate
             ResultSize     = $BatchSize               # per page, max 5000
             Operations     = $Operations
             SessionId      = $sessionId
             SessionCommand = 'ReturnLargeSet'         # request larger pages from UAL
             Formatted      = $true
         }
         $chunk = Search-UnifiedAuditLog @params
         if ($null -eq $chunk -or $chunk.Count -eq 0) { break }
         $all += $chunk
         $page++
         if ($page -gt 50) { break }                  # safety cap (max ~250k items)
     }
     $all | Sort-Object Identity -Unique | Sort-Object { $_.CreationDate -as [datetime] }
 }
 

# --- Fetch records ---
$Records = Get-UAuditRecords -StartDate $StartDateDt -EndDate $EndDateDt -Operations $Operations

# --- Counters (for summary) ---
$GroupLabels   = 0
$LabelsChanged = 0
$MisMatches    = 0
$NewDocLabels  = 0
$LabelsRemoved = 0
$LabelsRenamed = 0
$OfficeFileOpens = 0
$Downgrades    = 0

if (!$Records) {
    Write-Host "No audit records for sensitivity labels found."
    return
} else {
    Write-Host "Processing $($Records.Count) sensitivity labels audit records..."
}

# --- Report ---
# Normalize different audit payloads into a flat record with common fields.
$Report = [System.Collections.Generic.List[Object]]::new()

ForEach ($Rec in $Records) {
    # Initialize per-record vars
    $Document = $null; $Site = $null
    $LabelId = $null; $OldLabelId = $null
    $SiteLabelId = $null; $SiteLabel = $null
    $OldLabel = $null; $Label = $null
    $Device = $null; $Application = $null; $Reason = $null
    $EventCode = $null; $NewPriority = $null; $OldPriority = $null

    $AuditData = ConvertFrom-Json $Rec.AuditData
    $Target = [System.Web.HttpUtility]::UrlDecode($AuditData.ObjectId)

    switch ($AuditData.Operation) {

        "SensitivityLabelApplied" { # can be site/group, email, or desktop file
            if ($Rec.RecordType -eq "SharePoint") {
                # Site/group label
                $GroupLabels++
                $Reason  = "Label applied to site"
                $LabelId = $AuditData.ModifiedProperties.NewValue
                if (-not [string]::IsNullOrWhiteSpace($AuditData.ModifiedProperties.OldValue)) {
                    $OldLabelId = $AuditData.ModifiedProperties.OldValue
                }
                $Site = $AuditData.ObjectId
            }
            elseif ($AuditData.EmailInfo.Subject) {
                # Email apply (IDs sourced from SensitivityLabelEventData)
                $NewDocLabels++
                $Reason      = "Label applied to email"
                $Application = "Outlook"
                $Document    = "Email: " + $AuditData.EmailInfo.Subject
                $Site        = "Exchange Online mailbox"
                $LabelId     = $AuditData.SensitivityLabelEventData.SensitivityLabelId
                $OldLabelId  = $AuditData.SensitivityLabelEventData.OldSensitivityLabelId
                $EventCode   = $AuditData.SensitivityLabelEventData.LabelEventType
            }
            else {
                # Desktop file apply (local or synced path)
                $NewDocLabels++
                $Reason      = "Label applied to file (desktop app)"
                $LabelId     = $AuditData.SensitivityLabelEventData.SensitivityLabelId
                $Document    = $Target
                if ($Target -and $Target.Contains("/Shared")) {
                    $Site    = $Target.SubString(0, $Target.IndexOf("/Shared") + 1)
                }
                $EventCode   = $AuditData.SensitivityLabelEventData.LabelEventType
            }
            $Device      = $AuditData.DeviceName
            $Application = $AuditData.Application
        }

        "SensitivityLabelUpdated" { # Email explicit change
            $LabelsChanged++
            $Reason     = "Label changed on email"
            $LabelId    = $AuditData.SensitivityLabelEventData.SensitivityLabelId
            $OldLabelId = $AuditData.SensitivityLabelEventData.OldSensitivityLabelId
            $EventCode  = $AuditData.SensitivityLabelEventData.LabelEventType
            if ($AuditData.EmailInfo.Subject) {
                $Document    = "Email: " + $AuditData.EmailInfo.Subject
                $Site        = "Exchange Online mailbox"
                $Application = "Outlook"
            }
        }

        "SensitivityLabelRemoved" { # Email/desktop remove
            $LabelsRemoved++
            $Reason     = "Label removed"
            $LabelId    = $null
            # For removals, OldSensitivityLabelId holds the previous label
            $OldLabelId = $AuditData.SensitivityLabelEventData.OldSensitivityLabelId
            $EventCode  = $AuditData.SensitivityLabelEventData.LabelEventType
            if ($AuditData.EmailInfo.Subject) {
                $Document    = "Email: " + $AuditData.EmailInfo.Subject
                $Site        = "Exchange Online mailbox"
                $Application = "Outlook"
            } else {
                $Application = $AuditData.Application
                $Device      = $AuditData.DeviceName
            }
        }

        "FileSensitivityLabelApplied" {
            $NewDocLabels++
            $Reason     = "Label applied to document (Office Online)"
            $Document   = $AuditData.DestinationFileName
            $Site       = $AuditData.SiteURL
            $LabelId    = $AuditData.DestinationLabel
            $EventCode  = $AuditData.SensitivityLabelEventData.LabelEventType
        }

        "FileSensitivityLabelChanged" {
            $LabelsChanged++
            $Reason     = "Label changed in Office app"
            $Document   = $AuditData.SourceFileName
            $Site       = $AuditData.SiteURL
            $LabelId    = $AuditData.SensitivityLabelEventData.SensitivityLabelId
            $OldLabelId = $AuditData.SensitivityLabelEventData.OldSensitivityLabelId
            $EventCode  = $AuditData.SensitivityLabelEventData.LabelEventType
        }

        "FileSensitivityLabelRemoved" {
            $LabelsRemoved++
            $Reason     = "Label removed in Office app"
            $Document   = $AuditData.SourceFileName
            $Site       = $AuditData.SiteURL
            # Often only OldSensitivityLabelId is meaningful on remove
            $LabelId    = $AuditData.SensitivityLabelEventData.SensitivityLabelId
            $OldLabelId = $AuditData.SensitivityLabelEventData.OldSensitivityLabelId
            $EventCode  = $AuditData.SensitivityLabelEventData.LabelEventType
        }

        "DocumentSensitivityMismatchDetected" {
            $MisMatches++
            $Reason      = "Mismatch between document label and site label"
            $Document    = $AuditData.SourceFileName
            $Site        = $AuditData.SiteURL
            $LabelId     = $AuditData.SensitivityLabelId
            $SiteLabelId = $AuditData.SiteSensitivityLabelId
        }

        "SensitivityLabeledFileOpened" {
            $OfficeFileOpens++
            $Application = $AuditData.Application
            $Device      = $AuditData.DeviceName
            $LabelId     = $AuditData.LabelId
            $Document    = $AuditData.ObjectId
            $Site        = "Local workstation ($($AuditData.DeviceName))"
            $Reason      = "Labeled document opened by $($AuditData.Application)"
        }

        "SensitivityLabeledFileRenamed" {
            $LabelsRenamed++
            $Application = $AuditData.Application
            $Device      = $AuditData.DeviceName
            $LabelId     = $AuditData.LabelId
            $Reason      = "Labeled file edited locally or renamed"
        }

        "Assign label to group." {
            $GroupLabels++
            $Reason      = "Label assigned to Entra ID Group"
            $Target      = $AuditData.Target[3].Id
            $Application = $AuditData.Actor.Id[0]
            $LabelId     = $AuditData.ModifiedProperties[2].NewValue
        }
    } # end switch

    # --- Resolve names & priorities ---
    if ($LabelId)    { $Label     = $TenantLabels[$LabelId];     $NewPriority = $TenantLabelPriority[$LabelId] }
    if ($OldLabelId) { $OldLabel  = $TenantLabels[$OldLabelId];  $OldPriority = $TenantLabelPriority[$OldLabelId] }
    if ($SiteLabelId){ $SiteLabel = $TenantLabels[$SiteLabelId] }

    # --- Classify action (prefer LabelEventType; fallback to priority comparison) ---
    # LabelEventType: 1=Upgraded, 2=Downgraded, 3=Removed, 4=SameOrder
    $LabelAction = $null
    switch ($EventCode) {
        1 { $LabelAction = "Upgraded" }
        2 { $LabelAction = "Downgraded" }
        3 { $LabelAction = "Removed" }
        4 { $LabelAction = "No change" }
        default {
            if ($NewPriority -gt $OldPriority)      { $LabelAction = "Upgraded" }
            elseif ($NewPriority -lt $OldPriority)  { $LabelAction = "Downgraded" }
            elseif ($null -ne $OldPriority -and $null -ne $NewPriority) { $LabelAction = "No change" }
            else { $LabelAction = $Reason }
        }
    }

    if ($LabelAction -eq 'Downgraded') { $Downgrades++ }

    # --- Add to report ---
    $Report.Add([PSCustomObject]@{
        TimeStamp   = Get-Date($AuditData.CreationTime) -format g
        User        = $AuditData.UserId
        Target      = $Target
        Reason      = $Reason
        Label       = $Label
        LabelId     = $LabelId
        OldLabel    = $OldLabel
        OldLabelId  = $OldLabelId
        NewPriority = $NewPriority
        OldPriority = $OldPriority
        LabelAction = $LabelAction
        EventCode   = $EventCode
        Document    = $Document
        Location    = $Site
        SiteLabel   = $SiteLabel
        SiteLabelId = $SiteLabelId
        Device      = $Device
        Application = $Application
        Action      = $AuditData.Operation
    })
}

# --- Output ---
# Print a summary to the console and write detailed results to CSV.
Clear-Host
Write-Host "Job complete. $($Records.Count) Sensitivity Label audit records found for the last 180 days"
Write-Host ""
Write-Host ("Labels applied to SharePoint sites   : {0}" -f $GroupLabels)
Write-Host ("Labels applied to new documents      : {0}" -f $NewDocLabels)
Write-Host ("Labels updated on documents/emails   : {0}" -f $LabelsChanged)
Write-Host ("Labeled files edited locally/renamed : {0}" -f $LabelsRenamed)
Write-Host ("Labeled files opened (desktop)       : {0}" -f $OfficeFileOpens)
Write-Host ("Labels removed                       : {0}" -f $LabelsRemoved)
Write-Host ("Mismatches detected                  : {0}" -f $MisMatches)
Write-Host "----------------------"
Write-Host ""

$Report = $Report | Sort-Object { $_.TimeStamp -as [datetime] } -Descending

# Compute output paths (optionally append timestamp)
$CsvPath = $OutputCSVFile
$HtmlPath = $OutputHtmlFile
if ($AddTimestamp) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    function Add-FileSuffix([string]$Path, [string]$Suffix) {
        $dir = Split-Path -Parent $Path
        $name = Split-Path -Leaf $Path
        $base = [System.IO.Path]::GetFileNameWithoutExtension($name)
        $ext  = [System.IO.Path]::GetExtension($name)
        return (Join-Path $dir ("{0}{1}{2}" -f $base, $Suffix, $ext))
    }
    $CsvPath  = Add-FileSuffix -Path $OutputCSVFile  -Suffix ("_" + $stamp)
    $HtmlPath = Add-FileSuffix -Path $OutputHtmlFile -Suffix ("_" + $stamp)
}

# Ensure output directory exists
$outDir = Split-Path -Parent $CsvPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$Report | Export-Csv -NoTypeInformation $CsvPath
Write-Host "Report file written to $CsvPath"

# --- HTML Report ---
function ConvertTo-HtmlEscaped {
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )
    if ($null -eq $Text -or $Text -eq '') { return '' }
    return [System.Web.HttpUtility]::HtmlEncode($Text)
}

function Get-SortKey {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter()]$Value
    )
    if ($null -eq $Value) { return '' }
    switch ($Name) {
        'TimeStamp' {
            $dt = [datetime]::MinValue
            if ([datetime]::TryParse([string]$Value, [ref]$dt)) { return $dt.ToString('o') }
            else { return [string]$Value }
        }
        'NewPriority' { try { return ('{0:D10}' -f ([int]$Value)) } catch { return '0000000000' } }
        'OldPriority' { try { return ('{0:D10}' -f ([int]$Value)) } catch { return '0000000000' } }
        'EventCode'   { try { return ('{0:D10}' -f ([int]$Value)) } catch { return '0000000000' } }
        default { return ([string]$Value).ToLowerInvariant() }
    }
}

function New-InteractiveHtmlReport {
    param(
        [Parameter(Mandatory)] [System.Collections.IEnumerable]$InputObject,
        [Parameter(Mandatory)] [string]$Path,
        [Parameter()] [string[]]$Columns = @(
            'TimeStamp','User','Target','Reason','Label','LabelId','OldLabel','OldLabelId',
            'NewPriority','OldPriority','LabelAction','EventCode','Document','Location',
            'SiteLabel','SiteLabelId','Device','Application','Action'
        ),
        [Parameter()] [hashtable]$Summary = @{},
        # Logo parameters: provide either a single URL via -LogoUrl, or
        # dedicated variants for light/dark themes via -LogoUrlLight / -LogoUrlDark
        [Parameter()] [string]$LogoUrl,
        [Parameter()] [string]$LogoUrlLight,
        [Parameter()] [string]$LogoUrlDark,
        [Parameter()] [string]$LogoHref,
        [Parameter()] [string]$LogoAlt = 'Company Logo'
    )

    $rows = @()
    foreach ($r in $InputObject) {
        $cells = foreach ($c in $Columns) {
            $v = $null
            if ($r.PSObject.Properties.Match($c)) { $v = $r.$c }
            $text = if ($null -eq $v) { '' } else { [string]$v }
            $sortKey = Get-SortKey -Name $c -Value $v
            @{
                name=$c; text=$text; sort=$sortKey
            }
        }
        $rows += ,@{ cells = $cells }
    }

    $css = @'
:root{
  --bg:#0b1220; --elev:#0f172a; --muted:#94a3b8; --text:#e5e7eb;
  --accent:#60a5fa; --accent-strong:#3b82f6; --accent-darker:#2563eb; --border:#1f2a44;
  --chip:#1f2937; --chip-border:#334155;
  --ok:#16a34a; --ok-strong:#15803d; --ok-darker:#166534;
  --warn:#f59e0b; --warn-strong:#d97706; --warn-darker:#b45309;
  --bad:#ef4444; --bad-strong:#dc2626; --bad-darker:#b91c1c;
  --neutral:#64748b; --neutral-strong:#475569;
  --violet:#8b5cf6; --violet-strong:#7c3aed; --violet-darker:#6d28d9;
}
[data-theme="light"]{
  --bg:#f8fafc; --elev:#ffffff; --muted:#475569; --text:#0f172a;
  --accent:#2563eb; --accent-strong:#1d4ed8; --accent-darker:#1e40af; --border:#e2e8f0;
  --chip:#f3f4f6; --chip-border:#e5e7eb;
  --ok:#16a34a; --ok-strong:#15803d; --ok-darker:#166534;
  --warn:#b45309; --warn-strong:#92400e; --warn-darker:#78350f;
  --bad:#b91c1c; --bad-strong:#991b1b; --bad-darker:#7f1d1d;
  --neutral:#64748b; --neutral-strong:#475569;
  --violet:#7c3aed; --violet-strong:#6d28d9; --violet-darker:#5b21b6;
}
html,body{height:100%}
body{font-family:Inter,Segoe UI,Roboto,Arial,sans-serif;margin:0;color:var(--text);background:var(--bg)}
.container{max-width:1200px;margin:0 auto;padding:24px}
.header{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:16px;margin-bottom:12px;padding:12px 0}
.title{font-size:22px;font-weight:700;letter-spacing:.2px;display:flex;align-items:center;gap:10px}
.title img.logo{height:32px;width:auto;display:inline-block}
.title .logo-wrap{display:inline-flex;align-items:center;justify-content:center;padding:4px 6px;border-radius:8px;background:rgba(255,255,255,.06);border:1px solid var(--border);box-shadow:0 1px 2px rgba(0,0,0,.25)}
[data-theme="light"] .title .logo-wrap{background:rgba(0,0,0,.04);box-shadow:0 1px 2px rgba(0,0,0,.08)}
.title img.logo-light{display:none}
[data-theme="light"] .title img.logo-light{display:inline-block}
[data-theme="light"] .title img.logo-dark{display:none}
.meta{color:var(--muted);font-size:12px}
.toolbar{display:flex;gap:8px;align-items:center}
.theme-toggle{background:transparent;border:1px solid var(--border);color:var(--muted);padding:6px 10px;border-radius:6px;cursor:pointer}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:8px 0 12px}
.card{background:var(--elev);border:1px solid var(--border);border-radius:10px;padding:10px 12px;font-size:12px}
.card.metric{display:flex;flex-direction:column;gap:4px;min-width:160px;flex:1 1 180px}
.card.metric .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.4px;display:flex;align-items:center;gap:6px}
.card.metric .label .icon{font-size:14px;line-height:1}
.card.metric .value{font-size:22px;font-weight:700}
.card.metric.accent{border-color:var(--accent-strong)}
.card.metric.ok{border-color:var(--ok-strong)}
.card.metric.warn{border-color:var(--warn-strong)}
.card.metric.bad{border-color:var(--bad-strong)}
.card.metric.neutral{border-color:var(--neutral-strong)}
.controls{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;margin:12px 0 14px}
.toggles{display:flex;flex-wrap:wrap;gap:8px;background:var(--elev);border:1px solid var(--border);padding:8px 10px;border-radius:10px;max-height:120px;overflow:auto}
.toggle{font-size:12px;color:var(--muted)}
.toggle input{margin-right:6px}
.search{margin:0}
input[type="search"]{padding:8px 10px;width:320px;max-width:100%;border:1px solid var(--border);border-radius:8px;background:var(--elev);color:var(--text)}
table{border-collapse:separate;border-spacing:0;width:100%;font-size:12px;background:var(--elev);border:1px solid var(--border);border-radius:12px;overflow:hidden;box-shadow:0 6px 24px rgba(2,6,23,.28)}
th,td{border-bottom:1px solid var(--border);padding:10px 12px;vertical-align:top}
thead th{background:linear-gradient(180deg, rgba(99,102,241,.08), transparent);cursor:pointer;position:sticky;top:0;z-index:2}
th.sort-asc::after{content:' \25B2'; color:var(--muted); font-size:10px;}
th.sort-desc::after{content:' \25BC'; color:var(--muted); font-size:10px;}
tbody tr:hover{background:rgba(99,102,241,.06)}
.filters th{background:var(--elev);position:sticky;top:34px;z-index:1}
.filters input{width:100%;box-sizing:border-box;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:transparent;color:var(--text)}
.nowrap{white-space:nowrap}
.mono{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace}
.chip{display:inline-block;padding:2px 6px;border-radius:999px;background:var(--chip);border:1px solid var(--chip-border);color:var(--text)}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:600}
.badge.up{background:rgba(22,163,74,.15);color:#16a34a;border:1px solid rgba(22,163,74,.35)}
.badge.down{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.35)}
.badge.removed{background:rgba(234,179,8,.15);color:#ca8a04;border:1px solid rgba(234,179,8,.35)}
.badge.same{background:rgba(100,116,139,.15);color:#64748b;border:1px solid rgba(100,116,139,.35)}
.actions{display:flex;gap:8px}
.btn{background:var(--accent);color:#fff;border:1px solid var(--accent-strong);border-radius:8px;padding:8px 12px;font-size:12px;cursor:pointer}
.btn.secondary{background:transparent;color:var(--muted);border:1px solid var(--border)}
.btn.preset{background:#10b981;border-color:#059669}
/* Preset buttons: concise notes
   - Downgrades: prominent danger colors
   - Others: theme-aware accents
   - Use ID selectors for specificity */
   
    /* Downgrades button - standout color (default to darker shade) */
#btn-preset-downgrades{background:var(--bad-strong);border-color:var(--bad-strong);color:#fff;box-shadow:0 0 0 1px rgba(0,0,0,.05)}
#btn-preset-downgrades:hover{background:var(--bad-darker);border-color:var(--bad-darker)}

/* Standout styles for other preset buttons using theme variables */
#btn-preset-summary{background:var(--accent);border-color:var(--accent-strong);color:#fff}
#btn-preset-summary:hover{background:var(--accent-strong);border-color:var(--accent-darker)}

#btn-preset-email{background:var(--violet);border-color:var(--violet-strong);color:#fff}
#btn-preset-email:hover{background:var(--violet-strong);border-color:var(--violet-darker)}

#btn-preset-files{background:var(--warn);border-color:var(--warn-strong);color:#111827}
#btn-preset-files:hover{background:var(--warn-strong);border-color:var(--warn-darker);color:#fff}
'@

    $js = @'
function initTable(){
  const table=document.getElementById("report");
  const tbody=table.tBodies[0];
  const headers=table.tHead.rows[0].cells;
  const filterRow=table.tHead.rows[1];
  const filters=[...filterRow.querySelectorAll('.col-filter')];
  const q=document.getElementById('q');
  const btnClear=document.getElementById('btn-clear');
  const btnReset=document.getElementById('btn-reset-cols');
  const btnResetSort=document.getElementById('btn-reset-sort');
  const btnExportCsv=document.getElementById('btn-export-csv');
  const btnPresetSummary=document.getElementById('btn-preset-summary');
  const btnPresetEmail=document.getElementById('btn-preset-email');
  const btnPresetFiles=document.getElementById('btn-preset-files');
  const btnPresetDowngrades=document.getElementById('btn-preset-downgrades');
  const toggles=[...document.querySelectorAll('.col-toggle')];
  const storeKey='labelsReport:visibleCols';
  const themeKey='labelsReport:theme';
  const btnTheme=document.getElementById('btn-theme');

  // Sorting
  let sortCol=-1, asc=true;
  const baseOrder=[...tbody.rows];
  function updateSortClasses(col, dir){
    for(let i=0;i<headers.length;i++){ headers[i].classList.remove('sort-asc','sort-desc'); headers[i].removeAttribute('aria-sort'); }
    if(col>=0){ headers[col].classList.add(dir?'sort-asc':'sort-desc'); headers[col].setAttribute('aria-sort', dir?'ascending':'descending'); }
  }
  function sortBy(col){
    const rows=[...tbody.rows];
    const dir = (col===sortCol)?!asc:true; asc=dir; sortCol=col;
    rows.sort((a,b)=>{
      const av=a.cells[col].dataset.sort||a.cells[col].textContent.toLowerCase();
      const bv=b.cells[col].dataset.sort||b.cells[col].textContent.toLowerCase();
      if(av<bv) return dir?-1:1; if(av>bv) return dir?1:-1; return 0;
    });
    rows.forEach(r=>tbody.appendChild(r));
    updateSortClasses(col, dir);
  }
  for(let i=0;i<headers.length;i++){ headers[i].addEventListener('click',()=>sortBy(i)); }
  function resetSort(){ baseOrder.forEach(r=>tbody.appendChild(r)); sortCol=-1; updateSortClasses(-1,true); }

  // Filters
  function applyFilters(){
    const s=(q.value||'').toLowerCase();
    const colFilters=filters.map(inp=>({col:+inp.dataset.col, val:(inp.value||'').toLowerCase()}));
    for(const r of tbody.rows){
      let txt = s? r.textContent.toLowerCase() : '';
      if(s && txt.indexOf(s)===-1){ r.style.display='none'; continue; }
      let show=true;
      for(const f of colFilters){
        if(!f.val) continue;
        const cell=r.cells[f.col];
        const t=cell? cell.textContent.toLowerCase() : '';
        // Support simple OR filters using '|', e.g., "FileSensitivityLabel|SensitivityLabeledFile"
        const anyMatch = f.val.split('|').map(v=>v.trim()).filter(Boolean).some(v=> t.indexOf(v) > -1);
        if(!anyMatch){ show=false; break; }
      }
      r.style.display = show? '':'none';
    }
  }
  q.addEventListener('input',applyFilters);
  filters.forEach(inp=>inp.addEventListener('input',applyFilters));

  if(btnClear){
    btnClear.addEventListener('click',()=>{
      q.value='';
      filters.forEach(inp=>inp.value='');
      applyFilters();
    });
  }

  // Column visibility
  function setColVisibility(col, visible){
    table.tHead.rows[0].cells[col].style.display = visible? '':'none';
    if(table.tHead.rows[1]) table.tHead.rows[1].cells[col].style.display = visible? '':'none';
    for(const r of tbody.rows){ if(r.cells[col]) r.cells[col].style.display = visible? '':'none'; }
  }
  function saveState(){
    const vis=toggles.map(t=>t.checked?1:0);
    try{ localStorage.setItem(storeKey, JSON.stringify(vis)); }catch(e){}
  }
  function loadState(){
    try{
      const raw=localStorage.getItem(storeKey);
      if(!raw) return null;
      const arr=JSON.parse(raw);
      return Array.isArray(arr)? arr : null;
    }catch(e){ return null }
  }
  const saved=loadState();
  if(saved){ saved.forEach((v,i)=>{ if(typeof v==='number' && toggles[i]) { toggles[i].checked=!!v; } }); }
  toggles.forEach(t=>{
    setColVisibility(+t.dataset.col, t.checked);
    t.addEventListener('change',()=>{ setColVisibility(+t.dataset.col, t.checked); saveState(); });
  });

  if(btnReset){
    btnReset.addEventListener('click',()=>{
      toggles.forEach(t=>{ t.checked=true; setColVisibility(+t.dataset.col, true); });
      try{ localStorage.removeItem(storeKey); }catch(e){}
    });
  }

  if(btnResetSort){ btnResetSort.addEventListener('click',resetSort); }

  // Presets
  const colNames=[...headers].map(h=>h.textContent.trim());
  // Show initial sort indicator on TimeStamp (newest first / descending)
  const tsIndex = colNames.indexOf('TimeStamp');
  if(tsIndex >= 0){ updateSortClasses(tsIndex, false); }
  const colIndexMap = {}; colNames.forEach((n,i)=>colIndexMap[n]=i);
  function setFilterByName(name, value){
    const idx = colIndexMap[name];
    if(idx===undefined) return;
    const inp = filters.find(x=> +x.dataset.col === idx);
    if(inp){ inp.value = value || ''; }
  }
  function clearAllFilters(){ q.value=''; filters.forEach(inp=>inp.value=''); }
  function applyPresetVisibility(names){
    const want=new Set(names);
    toggles.forEach((t,i)=>{
      const show=want.has(colNames[i]);
      t.checked=show; setColVisibility(i, show);
    });
    saveState();
  }
  const presetSummary=['TimeStamp','User','Reason','Label','OldLabel','LabelAction','Action'];
  const presetEmail=['TimeStamp','User','Reason','Label','OldLabel','LabelAction','Document','Application','Action'];
  const presetFiles=['TimeStamp','User','Reason','Label','OldLabel','LabelAction','Document','Location','Device','Application','Action'];
  if(btnPresetSummary){ btnPresetSummary.addEventListener('click',()=>{ applyPresetVisibility(presetSummary); clearAllFilters(); applyFilters(); }); }
  if(btnPresetEmail){ btnPresetEmail.addEventListener('click',()=>{ applyPresetVisibility(presetEmail); clearAllFilters(); setFilterByName('Document','Email:'); applyFilters(); }); }
  if(btnPresetFiles){ btnPresetFiles.addEventListener('click',()=>{ applyPresetVisibility(presetFiles); clearAllFilters(); setFilterByName('Action','FileSensitivityLabel|SensitivityLabeledFile'); applyFilters(); }); }
  if(btnPresetDowngrades){ btnPresetDowngrades.addEventListener('click',()=>{ clearAllFilters(); setFilterByName('LabelAction','down'); applyFilters(); }); }

  // Export visible as CSV
  function exportVisibleCsv(){
    const cols=colNames;
    const lines=[cols.join(',')];
    for(const r of tbody.rows){
      if(r.style.display==='none') continue;
      const vals=[...r.cells].map(td=>{
        let v=td.textContent.replace(/\r?\n/g,' ').trim();
        if(v.indexOf('"')>-1) v=v.replace(/"/g,'""');
        if(v.indexOf(',')>-1 || v.indexOf('"')>-1) v='"'+v+'"';
        return v;
      });
      lines.push(vals.join(','));
    }
    const blob=new Blob([lines.join('\r\n')],{type:'text/csv;charset=utf-8;'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url; a.download='SensitivityLabelsAudit-visible.csv';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(()=>URL.revokeObjectURL(url), 1000);
  }
  if(btnExportCsv){ btnExportCsv.addEventListener('click',exportVisibleCsv); }

  // Theme toggle
  function applyTheme(t){ document.body.setAttribute('data-theme', t); try{ localStorage.setItem(themeKey,t);}catch(e){} }
  function currentTheme(){ try{ return localStorage.getItem(themeKey)||'dark'; }catch(e){ return 'dark' } }
  applyTheme(currentTheme());
  if(btnTheme){ btnTheme.addEventListener('click',()=>{ applyTheme(document.body.getAttribute('data-theme')==='dark'?'light':'dark'); }); }

  applyFilters();
}
document.addEventListener('DOMContentLoaded',initTable);
'@

    $summaryCards = @()
    foreach ($k in $Summary.Keys) {
        $v = [string]$Summary[$k]
        $cls = 'neutral'
        $valInt = 0; [void][int]::TryParse($v, [ref]$valInt)
        $lk = $k.ToLowerInvariant()
        # class by label and value
        if ($lk -match 'remov') {
            if ($valInt -gt 0) { $cls = 'bad' } else { $cls = 'neutral' }
        }
        elseif ($lk -match 'mismatch') {
            if ($valInt -gt 0) { $cls = 'warn' } else { $cls = 'neutral' }
        }
        elseif ($lk -match 'downgrade') { $cls = 'bad' }
        elseif ($lk -match 'new label') { $cls = 'ok' }
        elseif ($lk -match 'open|rename|change|site') { $cls = 'accent' }

        # normalize icon using HTML entities to avoid Unicode encoding issues
        $icon = Switch ($true) {
            ($lk -match 'rename')     { '&#9998;' }     # ✎
            ($lk -match 'new label')  { '&#10133;' }    # ➕
            ($lk -match 'site')       { '&#127760;' }   # 🌐
            ($lk -match 'change')     { '&#8635;' }     # ↻
            ($lk -match 'open')       { '&#128194;' }   # 📂
            ($lk -match 'mismatch')   { '&#9888;' }     # ⚠
            ($lk -match 'remov')      { '&#128465;' }   # 🗑️
            ($lk -match 'downgrade')  { '&#11015;' }    # ⬇
            Default                   { '&#9671;' }     # ◇
        }
        $summaryCards += '<div class="card metric ' + $cls + '"><div class="label"><span class="icon">' + $icon + '</span>' + (ConvertTo-HtmlEscaped $k) + '</div><div class="value">' + (ConvertTo-HtmlEscaped $v) + '</div></div>'
    }

    $th = ($Columns | ForEach-Object { '<th>' + (ConvertTo-HtmlEscaped $_) + '</th>' }) -join ""
    $trs = foreach ($row in $rows) {
        $tds = foreach ($cell in $row.cells) {
            $name = [string]$cell.name
            $tRaw = [string]$cell.text
            $t = ConvertTo-HtmlEscaped $tRaw
            $s = ConvertTo-HtmlEscaped $cell.sort
            $extraClass = @()
            if ($name -eq 'TimeStamp') { $extraClass += 'nowrap' }
            if ($name -in @('LabelId','OldLabelId','SiteLabelId')) { $extraClass += 'mono' }

            $display = $t
            if ($name -eq 'LabelAction' -and $tRaw) {
                $lc = $tRaw.ToLowerInvariant()
                $cls = if ($lc -match 'upgrade') { 'up' } elseif ($lc -match 'downgrade') { 'down' } elseif ($lc -match 'remove') { 'removed' } else { 'same' }
                $display = ('<span class="badge {0}">{1}</span>' -f $cls, $t)
            }
            elseif ($name -in @('Application','Device')) {
                $display = ('<span class="chip">{0}</span>' -f $t)
            }

            ('<td data-col="{0}" data-sort="{1}" class="{2}">{3}</td>' -f (ConvertTo-HtmlEscaped $name), $s, ($extraClass -join ' '), $display)
        }
        '<tr>' + ($tds -join '') + '</tr>'
    }

    $html = @()
    $html += '<!DOCTYPE html>'
    $html += '<html lang="en">'
    $html += '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    $html += '<title>Microsoft 365 Sensitivity Labels Audit</title>'
    $html += '<style>' + $css + '</style>'
    $html += '</head><body>'
    $html += '<div class="container">'
    $html += '<div class="header">'
    $logoHtml = ''
    # Resolve light/dark logo sources with fallbacks
    $srcLightRaw = if ($LogoUrlLight) { $LogoUrlLight } elseif ($LogoUrl) { $LogoUrl } else { $null }
    $srcDarkRaw  = if ($LogoUrlDark)  { $LogoUrlDark }  elseif ($LogoUrlLight) { $LogoUrlLight } elseif ($LogoUrl) { $LogoUrl } else { $null }
    if ($srcLightRaw -or $srcDarkRaw) {
        $alt = ConvertTo-HtmlEscaped $LogoAlt
        if ($srcLightRaw -and $srcDarkRaw -and ($srcLightRaw -ne $srcDarkRaw)) {
            $srcLight = ConvertTo-HtmlEscaped $srcLightRaw
            $srcDark  = ConvertTo-HtmlEscaped $srcDarkRaw
            $imgInner = '<img class="logo logo-dark" src="' + $srcDark + '" alt="' + $alt + '" />' +
                        '<img class="logo logo-light" src="' + $srcLight + '" alt="' + $alt + '" />'
            $img = '<span class="logo-wrap">' + $imgInner + '</span>'
        }
        else {
            $chosenSrc = if ($null -ne $srcDarkRaw) { $srcDarkRaw } else { $srcLightRaw }
            $src = ConvertTo-HtmlEscaped $chosenSrc
            $img = '<span class="logo-wrap"><img class="logo" src="' + $src + '" alt="' + $alt + '" /></span>'
        }
        if ($LogoHref) {
            $href = ConvertTo-HtmlEscaped $LogoHref
            $img = '<a class="logo-link" href="' + $href + '" target="_blank" rel="noopener">' + $img + '</a>'
        }
        $logoHtml = $img
    }
    $html += '<div class="title">' + $logoHtml + 'Microsoft 365 Sensitivity Labels Audit</div>'
    $html += '<div class="toolbar">'
    $html += '<button id="btn-theme" class="theme-toggle" type="button">Toggle Theme</button>'
    $html += '</div>'
    $html += '<div class="meta">Generated ' + (ConvertTo-HtmlEscaped ((Get-Date).ToString('yyyy-MM-dd HH:mm'))) + '</div>'
    $html += '</div>'
    if ($summaryCards.Count -gt 0) { $html += '<div class="cards">' + ($summaryCards -join '') + '</div>' }
    # Column visibility toggles + search
    $colToggles = for ($i=0; $i -lt $Columns.Length; $i++) { '<label class="toggle"><input type="checkbox" class="col-toggle" data-col="' + $i + '" checked> ' + (ConvertTo-HtmlEscaped $Columns[$i]) + '</label>' }
    $html += '<div class="controls">'
    $html += '<div class="toggles">' + ($colToggles -join '') + '</div>'
    $html += '<div class="search"><input id="q" type="search" placeholder="Search..." /></div>'
    $html += '<div class="actions">'
    $html += '<button id="btn-clear" class="btn secondary" type="button">Clear Filters</button>'
    $html += '<button id="btn-reset-cols" class="btn" type="button">Reset Columns</button>'
    $html += '<button id="btn-reset-sort" class="btn secondary" type="button">Reset Sorting</button>'
    $html += '<button id="btn-export-csv" class="btn" type="button">Export Visible CSV</button>'
    $html += '<button id="btn-preset-summary" class="btn preset" type="button">Preset: Summary</button>'
    $html += '<button id="btn-preset-email" class="btn preset" type="button">Preset: Email</button>'
    $html += '<button id="btn-preset-files" class="btn preset" type="button">Preset: Files</button>'
    $html += '<button id="btn-preset-downgrades" class="btn preset" type="button">Filter: Downgrades</button>'
    $html += '</div>'
    $html += '</div>'

    $html += '<table id="report">'
    $filterHeads = for ($i=0; $i -lt $Columns.Length; $i++) { '<th><input class="col-filter" data-col="' + $i + '" placeholder="Filter..." /></th>' }
    $html += '<thead><tr>' + $th + '</tr><tr class="filters">' + ($filterHeads -join '') + '</tr></thead>'
    $html += '<tbody>' + ($trs -join "") + '</tbody>'
    $html += '</table>'
    $html += '</div>'
    $html += '<script>' + $js + '</script>'
    $html += '</body></html>'

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $joined = ($html -join "")
    # Clean up any accidental backslash-escaped quotes that may appear in literals
    $joined = $joined.Replace('\"','"')
    [IO.File]::WriteAllText($Path, $joined, [System.Text.Encoding]::UTF8)
}

# Build summary map
$summary = @{
    'Sites labeled' = $GroupLabels
    'New labels'    = $NewDocLabels
    'Changes'       = $LabelsChanged
    'Downgrades'    = $Downgrades
    'Opens'         = $OfficeFileOpens
    'Renames'       = $LabelsRenamed
    'Removals'      = $LabelsRemoved
    'Mismatches'    = $MisMatches
}

# Generate HTML report
# Include Declarative logo in header by default; customize via parameters as needed
New-InteractiveHtmlReport -InputObject $Report -Path $HtmlPath -Summary $summary -LogoHref 'https://declarative.nz/' -LogoUrl 'https://images.squarespace-cdn.com/content/v1/678588088e803d11820d06a4/8b4949d5-1e98-4804-9d76-302086fe66c4/Declarative+Logo_Full_Positive.png' -LogoAlt 'Declarative'
Write-Host "HTML report written to $HtmlPath"

if ($OpenHtml) { try { Invoke-Item -LiteralPath $HtmlPath } catch {} }

if ($PassThru) {
    $Report
}
