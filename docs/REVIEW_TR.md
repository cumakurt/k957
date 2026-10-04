# k957 0.3.0 — Examiner review

`review` adds an examiner decision/reason to an automatic finding. Raw evidence stays unchanged; each update creates a new JSON review history. Applying reviews verifies evidence again and recomputes analysis. The historical filename is retained for existing links; this document is in English.

## Workflow

1. Analyze evidence:

```sh
k957 analyze --in case.k957 --rules rules.json --out initial-analysis
```

Copy the `F-...` finding ID from `analysis.json`, `findings.csv` or HTML. It is reproducible for the same manifest, rule, source and match position. New analysis run IDs do not change finding identity.

2. Create a first review:

```sh
k957 review --analysis initial-analysis/analysis.json \
  --finding F-COMPLETE_FINDING_ID --decision needs-review \
  --analyst "Examiner A" --note "Inspect the source record and user context." \
  --out review-v1.json
```

Decisions are `confirmed`, `rejected` or `needs-review`. They do not establish guilt, attribution or definitive maliciousness. Examiner/reason are required, bounded at 256 and 16,000 bytes respectively.

3. Preserve the previous file and append a decision:

```sh
k957 review --analysis initial-analysis/analysis.json \
  --previous review-v1.json --finding F-COMPLETE_FINDING_ID \
  --decision rejected --analyst "Examiner B" \
  --note "Confirmed as synthetic test data." --out review-v2.json
```

4. Apply the review:

```sh
k957 analyze --in case.k957 --rules rules.json \
  --reviews review-v2.json --out reviewed-report
```

Evidence manifest, rules, analyzer version and automatic findings must match. A mismatch prevents report generation. Findings retain their latest decisions, including rejected findings; all earlier events remain in `analysis.json` and the history table. `findings.csv` contains the latest decision, examiner and reason.

## Signed review

```sh
k957 keygen --out examiner-sign
k957 review --analysis initial-analysis/analysis.json \
  --finding F-COMPLETE_FINDING_ID --decision confirmed \
  --analyst "Examiner A" --note "Checked the source record." \
  --sign-key examiner-sign.key --out signed-v1.json
k957 analyze --in case.k957 --rules rules.json \
  --reviews signed-v1.json --review-key examiner-sign.pub --out signed-report
```

Appending signed history requires `--previous-key` to verify the prior signature and `--sign-key` for the new revision. Silent continuation as unsigned history is rejected. Signers may change; preserve prior files.

`--trusted-key` authenticates evidence; `--review-key` authenticates review history. A present signature without a trusted key is not reported as authenticated.

## Trust and limits

- Input `analysis.json` is not proof of evidence integrity. Applying reviews reopens/verifies actual evidence and recomputes findings.
- Review basis binds analyzer version, manifest SHA-256, rules and canonical automatic findings; run time/ID are excluded.
- Events form an ordered hash chain. An unsigned chain does not authenticate its author; an editor can recompute it.
- Ed25519 attests the complete new revision, not an application account, RBAC policy or each previous examiner's identity. Names are free text; organizations manage key ownership/trust.
- Deletion, rollback to valid old history or parallel branches require external retention/version controls. Complete history and trusted timestamps are not guaranteed; retain earlier signed revisions independently.
- Bounds are 10,000 review events and 32 MiB history; `LoadAnalysis` has a separate 128 MiB ceiling.
- HTML is escaped and CSV formula prefixes are neutralized. This does not establish browser/accessibility validation.
- Decisions use a CLI workflow; reports are not edited in the browser. Multi-user role/concurrency/mandatory independent second approval are not implemented. See [CASE.md](CASE.md) for the current read-only local viewer.
- Earlier analysis/review formats are not automatically migrated; reanalyze earlier v1/v2 evidence with the current version for new review work.
- Finish active older-version checkpoints with their original binary and analyze the final package separately. Never edit checkpoint version fields to force migration.
