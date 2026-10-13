# Validation matrix

| Detection | Test case | Expected | Actual | Outcome |
|---|---|---|---|---|
| T1098.003 | Monitoring Contributor + Log Analytics Contributor assigned to policy identity | No alert | No results | Pass |
| T1098.003 | Contributor assigned to lab-test-user via portal (v0.1 query) | Alert | No results - portal uses PascalCase fields | Fail -> fixed in v0.2 |
| T1098.003 | Contributor assigned to lab-test-user via portal (v0.2 query) | Alert | 1 row: Contributor, User, RG-SENTINEL-LAB | Pass |
| T1098.003 | User Access Administrator (unconstrained) assigned to lab-test-user via portal - scheduled rule | Incident created | Incident #1, Medium, ~13 min after the action | Pass |
| T1098.003 | UAA with "Recommended" condition assigned via portal - tuned rule | Incident with role in title, IP evidence | Incident #2: title shows UAA, IP entity mapped, ~13 min | Pass |
