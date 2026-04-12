Generated local datasets live in this directory and are intentionally not committed.

Typical generated artifacts include:

- `vuln_lookup.db`
- `ops.db`
- `kev.json`
- `epss_scores.json`
- `nvd/`
- `exploitdb/`

To rebuild the local vulnerability intelligence database and feed caches, run:

```bash
.venv/bin/python setup_datasets.py
```

The application will recreate `ops.db` automatically at runtime.
