# SOC 2 Incident Response Checklist

A free, static web app: prepare for a security incident before it happens, track one cleanly while it unfolds, and export the record afterward.

Maps to the AICPA Trust Services Criteria:

- **CC7.3** Security event triage and evaluation
- **CC7.4** Incident response
- **P6.5** Vendor breach notification commitments
- **P6.6** Breach notification to data subjects and regulators

## Features

- **Prepare tab**: 7-item incident readiness checklist with progress tracking, plus plain-English summaries of the four governing criteria (loaded from the shared TSC dataset).
- **Active incident tab**: start an incident (detection timestamp auto-recorded), work through 19 tasks across 6 phases (Detect/Triage, Contain, Eradicate, Recover, Notify, Lessons learned) with completion timestamps, and a live notification deadline tracker.
- **Notification tracker**: counts elapsed time since detection. You enter your own earliest deadline in hours. It deliberately states no single legal deadline: notification windows vary by contract and regulation, and P6.6 requires notification to affected data subjects and regulators per the entity's objectives.
- **Log & export tab**: timestamped incident log plus a one-click Markdown incident record (metadata, task states by phase, log, readiness snapshot).
- **Persistence**: everything saves to browser localStorage under the key `soc2incident`. No backend, no accounts, no external requests. Offline-capable once loaded.

## Run it

Open `index.html` in a browser, or serve the folder with any static server:

```sh
python3 -m http.server 8080
```

## Data

`data/tsc.json` is a copy of the machine-readable Trust Services Criteria dataset from [nehemiah313/tsc-dataset](https://github.com/nehemiah313/tsc-dataset) (61 criteria). Summaries are original plain-English guidance, not AICPA text.

## Disclaimer

Readiness aid only. Not legal advice. Consult counsel on breach notification obligations.

Built by AI Tech Pros. Part of the free SOC 2 readiness tool family. MIT licensed.
