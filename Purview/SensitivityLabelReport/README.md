# Export-SensitivityLabelsAuditRecords

Exports Microsoft 365 Sensitivity Label audit activity from the Unified Audit Log, enriches it with label metadata, and produces both a normalized CSV and an interactive HTML report.

## What It Does
- Queries label events across SharePoint/OneDrive, desktop Office apps, and Exchange Online using `Search-UnifiedAuditLog`.
- Resolves label GUIDs to display names and priorities via `Get-Label`, then classifies each event as an upgrade, downgrade, removal, or no-change.
- Normalizes event payloads into a consistent schema (user, workload, document/site context, devices/apps, label transitions).
- Summarizes the run (sites labeled, new labels, changes, downgrades, removals, mismatches, etc.) in both console output and HTML summary cards.

## Outputs
- `SensitivityLabelsAuditRecords.csv` – full dataset (optionally timestamped via `-AddTimestamp`).
- `SensitivityLabelsAuditRecords.html` – interactive report with filters, presets, and summary metrics.
- Console summary highlighting counts for Sites labeled, New labels, Changes, Downgrades, Opens, Renames, Removals, and Mismatches.
- Optional pipeline output when `-PassThru` is supplied (objects are emitted to the PowerShell pipeline).

## Prerequisites
- Exchange Online session: `Connect-ExchangeOnline`
- Microsoft Purview (Security & Compliance) session: `Connect-IPPSSession`
- Roles that allow `Search-UnifiedAuditLog` and `Get-Label` (for example, View-Only Audit Logs, Compliance Administrator)

## Quick Start
```powershell
# Connect
Connect-ExchangeOnline
Connect-IPPSSession

# Run with defaults (last 180 days) and open HTML when done
./Export-SensitivityLabelsAuditRecords.ps1 -OpenHtml

# Last 7 days, timestamped outputs, also return objects to the pipeline
./Export-SensitivityLabelsAuditRecords.ps1 -StartDate -7 -EndDate 0 -AddTimestamp -PassThru
```

## Parameters (high level)
- `-StartDate` / `-EndDate` – Accept DateTime literals (`'2025-08-01'`), integer day offsets (`-7`, `0`), relative strings (`'-12h'`, `'+3d'`), or keywords (`today`, `yesterday`, `now`).
- `-OutputCsvFile` – Destination for the CSV. Default: `./SensitivityLabelsAuditRecords.csv`.
- `-OutputHtmlFile` – Destination for the HTML report. Default: `./SensitivityLabelsAuditRecords.html`.
- `-AddTimestamp` – Appends `yyyyMMdd-HHmmss` to both output filenames (useful for retaining history).
- `-PassThru` – Emits the normalized records to the pipeline in addition to writing files.
- `-OpenHtml` – Launches the generated HTML file when the run completes.

## HTML Report Highlights
- Sortable headers with visual indicators (triangle glyphs) and a sticky filter row directly beneath the header.
- Global search and per-column filters with simple OR support (`A|B`), plus quick `Clear Filters` and `Reset Sorting` controls.
- Column visibility toggles whose state persists in the browser (`localStorage`), with a `Reset Columns` option.
- Presets for Summary, Email, Files, and Downgrades that adjust visibility and seed common filters in one click.
- Summary cards with iconography and status-aware color accents reflecting the run totals.
- Device and application columns render as compact “chip” pills; label actions surface as colored badges (Upgraded, Downgraded, Removed, Same).
- Dark/light theme toggle, persisted in `localStorage`, and header logo parameters (`-LogoUrl*`) for easy rebranding.
- “Export Visible CSV” downloads exactly what is currently displayed (filtered rows and visible columns).

## Summary Metrics
- Sites labeled – Count of site-level labeling events.
- New labels – Files or emails newly labeled.
- Changes – Upgrades/downgrades that altered the applied label.
- Downgrades – Label priority decreased relative to the previous label.
- Opens – Desktop Office open events for labeled files.
- Renames – Detected label rename events.
- Removals – Label removal actions.
- Mismatches – Document/site sensitivity mismatches detected.

## CSV Columns
`TimeStamp, User, Target, Reason, Label, LabelId, OldLabel, OldLabelId, NewPriority, OldPriority, LabelAction, EventCode, Document, Location, SiteLabel, SiteLabelId, Device, Application, Action`

## Notes
- Default lookback is 180 days; actual coverage depends on your tenant’s audit retention policies.
- Large result sets use `SessionCommand = ReturnLargeSet` (up to 5,000 rows per page with a safety cap).
- Classification prefers `LabelEventType` when available; otherwise the script compares label priorities.
- Output is sorted newest-first by `TimeStamp`; the HTML initializes with the same ordering.
- The HTML header branding defaults to Declarative assets—update the `New-InteractiveHtmlReport` call near the end of the script to drop in your own logos/links.
- `-AddTimestamp` affects both output files so they remain aligned in automation scenarios.

## Design Notes
For UI/UX rationale, theming variables, and extension points, see:
- `Purview/Export-SensitivityLabelsReport/Export-SensitivityLabelsReport-DesignNotes.md`

## Troubleshooting
- If prompted to connect, ensure both Exchange Online and Purview sessions are active.
- No results? Expand the date window, confirm audit logging is enabled, and verify retention coverage for the workloads you expect.
- Date parsing accepts flexible inputs; if an argument is rejected, try quoting it (e.g., `'2025-08-01'`) or switching to an explicit `Get-Date` expression.
- Use `-PassThru | Format-Table` to inspect the normalized records when debugging pipelines.

```
# Script entry
Purview/Export-SensitivityLabelsAuditRecords.ps1
```
