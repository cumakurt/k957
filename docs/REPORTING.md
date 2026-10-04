# Examination reports

## Default outputs

`analyze`, `share`, `case` and `case-bookmark` generate both `report.html` and `report.pdf`. No browser, model endpoint or network service is needed to generate the native PDF. `documents.json` identifies the source projection digest, included formats, PDF page count, glyph substitutions and reading-edition omissions.

```sh
k957 analyze --in ./evidence.k957 --out ./report --rules ./rules.json --iocs ./indicators.json
k957 share --in ./evidence.k957 --out ./shared
k957 case --root ./output --out ./case-dossier --iocs ./indicators.json
k957 report-documents --analysis ./report/analysis.json --out ./word-and-pdf --format both
k957 report-seal --report ./report --key ./examiner.key
k957 report-verify --report ./report --trusted-key ./examiner.pub
```

The native PDF is a reading edition, with embedded DejaVu fonts, numbered sections, source hashes/references and folios. HTML provides filtering, page navigation, review-state counts and labelled UTC activity distribution. Histogram counts describe source rows; they are not a severity score. Printing HTML includes all finding/inventory rows in the analysis projection, regardless of the current page/filter, then restores the interactive state.

Keep the report-signing private key outside the bundle. `report-seal` rejects the active key file, hard links to it and exact key-file copies in the bundle; rejected operations preserve the key and write no seal. This check is not a general scan for secrets in arbitrary text or RAM results. Shared exports observe caller cancellation across JSON/CSV/HTML/PDF and remove their newly created incomplete bundle; existing output directories are never replaced.

## Scope and omissions

PDF/DOCX text is limited to 16 KiB per paragraph and 1 MiB aggregate. Reading editions sample up to 500 findings, events, inventory objects, IOC matches and review records, 200 notes/coverage records, 400 acquisition issues, and 30 memory observation previews per image. Case PDFs sample up to 200 rows of each included index kind. `documents.json` discloses omissions. These are presentation limits: **complete RAM scan JSONL and external kernel outputs have no automatic result-count or image/output-size cap**. Full result names/counts/hashes and kernel method statuses appear before general findings.

Unsupported PDF glyphs are visible `[U+XXXX]` escapes recorded in the receipt. Original text remains in HTML/JSON; DOCX preserves Unicode text for an appropriate viewer/font. Report generation does not establish original evidence authenticity. Verify the signed collection/package and independently retained trust anchor.

Private memory JSONL contains reconstructable printable strings and may include credentials or other sensitive data. Full reports, IOC values, process references and recovered files require examiner review before disclosure. Shared PDF uses only the masked shared projection, excludes complete memory strings/kernel dump files and has its own disclosure binding. It cannot reproduce private full-report content.

`report-documents` generates a reading edition from the loaded analysis record; it does not reconstruct or copy missing complete memory sidecars. Inspect those in the original report bundle. A bundle seal covers included files and source/disclosure bindings; it does not prove every original acquired byte was semantically interpreted.

Report seals have no fixed manifest-size or file-count ceiling. The version 1 signature format remains compatible with existing seals. Verification requires a regular manifest file, checks its identity/size/modification time around the read, and supports cancellation. Failed or canceled seal writes remove only their newly created partial files. The exact JSON bytes and decoded inventory still occupy RAM; this is not a constant-memory verifier. General analysis/case input limits still apply when extracting source bindings.

## Offline indicator lists

Use an examiner-controlled `k957-indicators/1` JSON file:

```json
{
  "schema": "k957-indicators/1",
  "name": "Case indicators",
  "source": "Examiner-supplied list",
  "indicators": [
    {"id": "domain-1", "kind": "domain", "value": "example.test"},
    {"id": "ip-1", "kind": "ip", "value": "192.0.2.1"}
  ]
}
```

Kinds are exact `sha256`, `ip` and ASCII/punycode `domain`. IDs are unique. Input is bounded to 32 MiB; duplicate JSON keys/unknown fields are rejected. Domains are case folded and their trailing dot removed. Subdomains are not matched implicitly. Source/destination event IPs, parsed browser URL hosts, DNS questions, HTTP Host and TLS server names are supported. Collected object and memory hashes match SHA-256 indicators. Arbitrary prose, DNS answer reputation, active domain resolution and online malware engines are not queried. `indicators.json` and `indicator-matches.csv` retain list provenance and original event/native/packet references. Matches are observations, not automatic findings or compromise verdicts. Case queries support `--kind indicator_match`.

## Portable analysis

- `timeline.jsonl` supplies the required Timesketch `datetime`, `message`, `timestamp_desc` fields, plus original references/raw time. Events without an absolute timestamp are omitted from this file and retained in the ordinary analysis/CSV; `portable-exports.json` records this scope. [Timesketch schema](https://timesketch.org/guides/user/import-from-json-csv/).
- `file-sha256.txt` and `ip-addresses.txt` contain sorted observed values from the analysis projection. These are private lists of observations, not a blacklist or a complete list of all values anywhere in evidence bytes.
- `review-queue.json` gives a documented order: confirmed decisions, explicit further-review/hash candidates, structured predicates, literal candidates and rejected decisions. Volume does not change priority and no probability is implied.
- A rule may carry `"techniques": ["T1059.001"]`. `attack-navigator.json` follows layer format 4.5 and `attack-mappings.json` retains source-linked finding mappings. Scores count non-rejected findings in this projection. ID syntax is checked; membership in a particular ATT&CK release and semantic correctness are the examiner's responsibility. No technique is inferred from a word. [MITRE layer specification](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md).

The original analysis, full memory sidecars, JSON/CSV and case SQLite index remain authoritative examination projections. Each records its own supported scope and limits. See [next development scopes](DEVELOPMENT_PLAN.md).

## Current check scope

The retained Linux AMD64 upgrade receipt passed 35/35 checks. A separately recorded real Volatility 3 suite discovered and attempted 60 Linux/global methods on an invalid synthetic image, retained 58 failures and reported two unavailable optional modules. Successful empty projections in this negative exercise do not establish kernel-object recovery. A separate >8 GiB synthetic executable fixture checks full I/O, counts and dump/thread orchestration. Positive reference-image accuracy remains open. [Measurements](TEST_REPORT.md).

## USN records

Full analysis reports include `usn.csv` and structured journal events in `analysis.json`; PDF/DOCX timeline rows retain native record and file/parent references within reading-edition bounds. Shared reports exclude journal filenames and raw USN-specific identifiers. See [USN journal examination](USN_JOURNAL.md).

USN examination also emits `usn-files.json` and `usn-files.csv`: source-scoped file record groups with names, parent IDs, reason flags and original record references. HTML/PDF show up to 100 groups with five names/parents each; group/name/parent omissions are disclosed. Full exports cover all emitted USN records, subject to the original parser coverage. These are observations, not reconstructed file lifetimes or paths.
