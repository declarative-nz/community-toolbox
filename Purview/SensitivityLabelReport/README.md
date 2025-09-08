# Export-SensitivityLabelsAuditRecords

Exports Microsoft 365 Sensitivity Label audit records from the Unified Audit Log to CSV and an interactive HTML report.

## Prerequisites
- Exchange Online session: `Connect-ExchangeOnline`
- Microsoft Purview (Security & Compliance) session: `Connect-IPPSSession`
- Permissions to run `Search-UnifiedAuditLog` and `Get-Label` (e.g., View-Only Audit Logs, Compliance Administrator)

## Quick Start
```powershell
# Connect
Connect-ExchangeOnline
Connect-IPPSSession

# Run with defaults (last 180 days) and open HTML when done
./Export-SensitivityLabelsAuditRecords.ps1 -OpenHtml
```

## Parameters (high level)
- `-StartDate` / `-EndDate`: Accept DateTime (e.g. `'2025-08-01'`), integer day offsets (e.g. `-7`, `0`), relative strings (`'-12h'`, `'+3d'`), and keywords (`today`, `yesterday`, `now`).
- `-OutputCsvFile`: Path for CSV output. Default: `./SensitivityLabelsAuditRecords.csv`.
- `-OutputHtmlFile`: Path for HTML report. Default: `./SensitivityLabelsAuditRecords.html`.
- `-AddTimestamp`: Appends a timestamp (yyyyMMdd-HHmmss) to both CSV and HTML filenames (useful for pipelines/history).
- `-PassThru`: Also returns the report objects to the pipeline.
- `-OpenHtml`: Opens the generated HTML report after creation.

## HTML Report Features
- Sortable columns with visual indicators
- Global search and per-column filters (supports `A|B` OR matching)
- Column visibility toggles with saved state
- Presets: Summary, Email, Files + a Downgrades quick filter
- Summary metric tiles with icons and color cues
- Dark/light theme toggle (persisted)
- “Export Visible CSV” downloads the currently filtered table

## CSV Columns
`TimeStamp, User, Target, Reason, Label, LabelId, OldLabel, OldLabelId, NewPriority, OldPriority, LabelAction, EventCode, Document, Location, SiteLabel, SiteLabelId, Device, Application, Action`

## Notes
- Default lookback is the last 180 days; actual availability depends on your tenant’s audit retention.
- Large result sets are paged via `SessionCommand = ReturnLargeSet` (up to 5,000 per page, capped for safety).
- Classification uses `LabelEventType` when available; otherwise compares label priorities.
- The dataset is sorted newest-first by `TimeStamp` before export; the HTML indicates TimeStamp sorted descending.

## Design Notes
For UI/UX rationale, theming variables, and extension points, see:
- `Purview/Export-SensitivityLabelsReport-DesignNotes.md`

## Troubleshooting
- If you see "connect to Exchange Online" or Purview errors, ensure both sessions are connected.
- If no results are returned, widen the date window or confirm audit logging and retention in your tenant.
- Date parsing supports flexible inputs; if an input is rejected, try a quoted DateTime (e.g., `'2025-08-01'`).

```
# Script entry
Purview/Export-SensitivityLabelsAuditRecords.ps1
```
