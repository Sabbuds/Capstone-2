# Live demo samples

Small, predictable files for presenting the scanner UI. They are not part of the labeled
evaluation corpus (`samples/sqli`, `samples/command`), so editing them does not change the
regression tests or the published TP/FP/TN/FN numbers.

Start the UI with command repair enabled:

```powershell
.\scripts\ui.ps1 -CommandProfile linux-gnu-cat
```

| Pick in the dropdown (Live demo group) | Expected result |
| --- | --- |
| All demo files | 5 vulnerabilities with 3 repair proposals and 2 manual fixes. Accuracy TP 5, FN 0, FP 0, TN 2 |
| CustomerLookup | 3 SQL injections with 2 proposals (SELECT, UPDATE) and 1 manual fix (`ORDER BY` column) |
| FileViewer | 2 command injections with 1 proposal (`sh -c cat`) and 1 manual fix (`ping`) |
| SafeReports | 0 findings, including an `ORDER BY` protected by an allowlist |

Without `-CommandProfile`, the `sh -c cat` finding moves to "needs manual fix" and the card explains why.

Suggested order: CustomerLookup (open "Show proposed change" and the "With proposals"
code view, download the proposed file, then show the refused `ORDER BY` and why a human must fix it), FileViewer, SafeReports (no
false alarms), then "SQL injection set" for the accuracy chart. Click a chart bar to list the
methods behind it. "Export HTML report" saves the current results for write-ups.

`EXPECT_*` labels here sit on their own line above the vulnerable call. The SQL repairer refuses
lines ending in a comment, so the corpus style (`call(); // EXPECT_SQLI`) would turn every repair
into a manual fix.
