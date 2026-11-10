# Reference data

Local snapshots used for exploitability scoring, so nothing leaves the machine at scan time.

| File | Tracked in git | What it is |
|---|---|---|
| `kev_snapshot.json` | yes | Small curated subset of the CISA KEV catalog for the offline demo |
| `epss_snapshot.csv` | yes | Small subset of EPSS scores with **approximate, illustrative** values |
| `kev_full.json` | no | Full CISA KEV catalog, written by `webscan refresh-reference-data` |
| `epss_full.csv.gz` | no | Full daily EPSS scores, written by `webscan refresh-reference-data` |

When the full files exist they are used instead of the bundled subsets (except in
`webscan demo`, which always uses the bundled subsets so the demo is repeatable).

The refresh command downloads two public files and sends no target data.
