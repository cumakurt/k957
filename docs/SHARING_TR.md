# Masked sharing report — v0.8.0

`share` reanalyzes verified evidence and produces a **separate sharing report**. It does not modify raw evidence, original analysis, examiner decisions or custody records. HTML/JSON/CSV use one restricted projection; the original `analysis.json` is not edited by text substitution. The historical filename is retained; this document is in English.

## Default usage

```sh
k957 share --in /evidence/case.k957 --out /sharing/case-001 \
  --rules /rules/rules.json --trusted-key /secure/acquisition.pub
```

Rules/trusted key are optional. Object hashes are always verified; an external trusted key authenticates acquisition. Unseal encrypted packages first in an authorized environment.

Without a policy, case names, users/actors, hosts, IPs, paths and locations receive aliases, and source times are omitted. A repeated path appears consistently as `[PATHS-000001]` within that report. Aliases are category-specific; they do not merge identities across categories.

Each report gets a new ID. Evidence, rules and findings receive local IDs. Original hashes, signatures, package/run identities and reverse mappings are omitted. Shared files cannot independently verify original evidence or serve as `review` input.

## Explicitly retained fields

```json
{"schema":"k957-share-policy/1","keep":["timestamps"],"literals":["Customer A","PrivateProject"]}
```

```sh
k957 share --in /evidence/case.k957 --out /sharing/case-002 \
  --rules /rules/rules.json --policy /secure/sharing.json
```

- `case`: case name.
- `users`: structured-record user fields.
- `hosts`: collector and structured-record hosts.
- `ips`: parsed source/destination IPs and related correlations.
- `paths`: source paths/references.
- `actors`: operator, examiner and custody parties.
- `locations`: custody locations.
- `timestamps`: structured source/event/review/custody times.

Empty `keep` masks/removes every category. Names are lowercase; unknown/duplicate selections are rejected.

Retained **text fields** still replace known values from masked categories and additional `literals` with `[MASKED]`. Retaining paths while masking users also removes known usernames from those paths. A value retained as a user can still be masked because it matches a masked actor. Longer matches win. Matching uses case-insensitive Unicode simple folding; regex metacharacters are literal. Unicode normalization, alternative spellings, URL encoding and alternative IP representations are not automatically recognized.

Literal contents are omitted from reports; only their count is retained. They apply to retained source text, rather than fixed labels, generated aliases or numeric fields. Timestamp policy covers structured times, not dates embedded in retained filenames.

## Always omitted

There is no option to retain arbitrary free text. Finding quotations, event descriptions, rule names/content/descriptions, source scope, examiner reasons, custody notes, error details and original method notes are omitted even when a related category is retained. This prevents unparsed text from silently exposing unknown personal details.

Sizes/counts, collection status/issue totals, parse counts, line/byte positions, relationships, decisions and ordering remain. They can assist reidentification; anonymity is not guaranteed. Original reports retain detailed methods/limitations. Sharing output alone does not replace a complete examination.

## Signed reviews and custody

```sh
k957 share --in /evidence/case.k957 --out /sharing/case-003 \
  --rules /rules/rules.json \
  --reviews /records/reviews.json --review-key /secure/examiner.pub \
  --custody /records/custody.json --custody-trust /secure/trust.json \
  --custody-head INDEPENDENT_CURRENT_HEAD
```

Original analysis is recomputed and review/custody inputs are verified before projection. Failure prevents sharing output. Original signatures/chains cannot authenticate changed masked content and are not copied into it. HTML identifies the report as derived. Separate current report seals are documented in [EXAMINATION_WORKFLOWS.md](EXAMINATION_WORKFLOWS.md).

## Outputs

- `report.html`: searchable offline English sharing report.
- `shared.json`: `k957-shared-report/1` projection, distinct from analysis JSON.
- `evidence.csv`, `findings.csv`, `timeline.csv`, `correlations.csv`, `reviews.csv`.
- `custody.csv` when custody events exist.
- `network.csv` and `captures.csv` when their network projections exist.

Evidence, original reports, rules/policies, keys and acquisition signatures are not copied into the sharing directory. Project examples include unmasked synthetic sources/reports. Share only the inspected **sharing output directory**; do not add original sources afterward.

Existing directories are rejected. Generation failures attempt to remove the new directory. Output is unencrypted; manage access/transport separately.

## Resource bounds and validation

Policy bounds: 1 MiB, 100 literals, 512 UTF-8 bytes per literal. Cross-field replacement permits at most 20,000 unique patterns and 1 MiB escaped pattern text. Bounds/compiler complexity failure prevents output. Fully masked default policy does not require the retained-text matcher.

Tests check private markers across all files, consistent aliases, cross-field masking, longer-match priority, HTML/CSV safety and unchanged original analysis. `scripts/share_integration.py` checks signed review/custody inputs and original byte hashes. Missing known synthetic markers does not establish automatic discovery of every real-world personal detail.

Complete old checkpoints with their original binary. v1/v2 packages remain readable; reviews stay analyzer-version-bound, while custody format remains independent.

## Network projection

Masked packet events, directional flows and coverage retain protocol/ports/flags, frame lengths, counts and packet/byte positions. IPs/paths start masked and source timestamps omitted. The projection does not provide anonymity or complete network interpretation. See [PCAP_TR.md](PCAP_TR.md).
