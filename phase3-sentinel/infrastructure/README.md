# Infrastructure: data collection rules

ARM templates of the two data collection rules that send the laptop's events to the Log Analytics workspace, exported from the Azure portal on 2026-10-20:

- `dcr-windows-security.template.json`: Security log, events 4624, 4625, 4688 and 4740 into SecurityEvent.
- `dcr-sysmon.template.json`: Sysmon operational log, events 1 and 13 into the Event table.

The subscription ID in the workspace `defaultValue` is replaced by `<subscription-id>`; pass the real workspace resource ID when deploying.

Not included: the association between each rule and the Azure Arc machine (a separate resource), the Arc agent, and the Sysmon installation and its configuration. These templates repeat the cloud side only.
