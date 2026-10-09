# Baseline prioritization engine

The engine implements [methodology v0.1](prioritization-methodology.md) and consumes
[Threat Velocity](threat-velocity.md). Tiers express public-intelligence review
order, with provisional thresholds. They do not establish asset applicability,
calibrated risk, compromise probability, or remediation deadlines.

## Evaluate and replay

From the repository root, evaluate stored PostgreSQL evidence:

```sh
uv run --locked python -m threatpulse.priority --output data/priority-first
```

`DATABASE_URL` is required for database input. Apply the existing migrations
first; the engine uses a REPEATABLE READ, READ ONLY transaction and performs no
collection or database writes. It adds no dependencies, schema, or access keys.
An empty database produces an honest empty report.

Run the self-contained synthetic example without a database or network:

```sh
uv run --locked python -m threatpulse.priority \
  --input tests/fixtures/priority_dataset.json --output data/priority-demo
```

Its ten invented CVEs cover all six queues, including historical catalog removal,
missing CVSS, Rejected status, source conflict, stale EPSS, and an eligible rise
using an explicitly invented model-regime declaration. These are not findings
about real vulnerabilities and do not validate the thresholds.

Replay the frozen inputs with the recorded decision time and same code/locked
environment. Always choose a new output directory:

```sh
uv run --locked python -m threatpulse.priority \
  --input data/priority-demo/source.json \
  --decision-at 2026-01-10T12:00:00Z --output data/priority-replay
```

Each report contains `source.json`, `policy.json`, `analysis.json`, `decisions.csv`,
`report.html`, and `manifest.json`. HTML shows the first 20 CVEs per queue in
neutral CVE-identifier order; JSON/CSV preserve the full cohort. UNDETERMINED has
its own visible queue. Nested CSV values are sorted JSON; missing values remain
distinct from zero. Reports include source-quality causes, trend coverage and
failed gates, decision/input/policy hashes, review outcomes, and limitations.
The manifest records file/code SHA-256 hashes and Python/package versions.
`policy_sha256` hashes canonical compact JSON; the manifest separately hashes
the actual pretty-printed `policy.json` bytes.

## Preserve decisions between evaluations

On **every subsequent run**, supply the previous report's analysis:

```sh
uv run --locked python -m threatpulse.priority \
  --previous data/priority-first/analysis.json --output data/priority-next
```

There is no implicit PostgreSQL priority state. Keep report directories and track
the latest successful analysis file as part of scheduling. The existing daily
ingestion schedule does not automatically evaluate priorities. Omitting previous
decisions starts a new baseline and cannot protect tiers from previous reports.
The engine carries known positive KEV evidence forward and retains previous
cohort CVEs missing from a new source export, rather than silently dropping them.
Corrupted decision checksums and future previous decisions fail validation.

Stronger candidates take effect immediately. A weaker candidate, including
UNDETERMINED or OUT_OF_SCOPE, retains the previous P1–P4 tier and adds
`DOWNGRADE_REVIEW_REQUIRED`. `candidate_tier` explains the proposal;
`effective_tier` drives the queue. Optional missing trend history alone does not
make `needs_review` true; required unknown inputs and source conflicts do.

## Record a downgrade review

Inspect the proposed decision in `analysis.json`. Create a JSON **array** of
acknowledgements, copying the exact identifiers from that decision:

```json
[
  {
    "review_id": "review-2026-01-10-1234",
    "reviewer": "Reviewer name",
    "reviewed_at": "2026-01-10T12:30:00Z",
    "rationale": "Explain the reviewed evidence and accepted weaker candidate.",
    "cve_id": "CVE-2026-1234",
    "policy_version": "0.1",
    "policy_sha256": "COPY_FROM_PROPOSED_DECISION",
    "previous_decision_id": "COPY_FROM_PROPOSED_DECISION",
    "input_sha256": "COPY_FROM_PROPOSED_DECISION",
    "approved_candidate": "P4"
  }
]
```

The placeholders make this a template, not a valid approval. For an actual review,
re-evaluate the **same proposed report's frozen source**, whose embedded previous
decision is the one being acknowledged:

```sh
uv run --locked python -m threatpulse.priority \
  --input data/priority-next/source.json --reviews reviews.json \
  --decision-at REVIEWED_AT_ISO8601 --output data/priority-reviewed
```

Do not attach the proposal itself as `--previous` while approving that proposal;
doing so creates a different previous-decision identifier. On the following normal
evaluation, carry `data/priority-reviewed/analysis.json` as the new previous file.

Reviews require a name, rationale, aware timestamp at/after the frozen export and
previous decision, and exact policy/input/previous/candidate matching. Future or
mismatched records cannot lower the tier; `review_audit` records each failed check.
A forward evaluation clock is allowed without changing evidence timestamps.
The fingerprint binds the source versions, catalog history, registry, previous
decision, source corrections, quality states, and trend eligibility. Clock passage
alone does not change the fingerprint while these classifications stay identical;
changed evidence, expired freshness, changed eligibility, policy, or candidate
requires a new acknowledgement. Original EPSS/NVD/CISA freshness limits still apply.

These are trusted operator files, not signed reviews or identity authentication.
Protect their write access and preserve the report chain. Checksums detect
accidental edits; a party allowed to rewrite records can also recompute checksums.

## Evidence and freshness

`PriorityDataset` uses `dataset_kind=baseline_priority`, `schema_version=1`, an
aware `captured_at`, an explicit cohort, and arrays of catalog, KEV, NVD, and EPSS
evidence. Each evidence wrapper requires a unique `evidence_id`, `source_url`,
aware `captured_at`, and `available_at` at/after capture. Only evidence available
by `decision_at` is used. Duplicate identities/cohort CVEs, ambiguous EPSS CVE/date
observations, invalid provenance/schema, and out-of-cohort evidence fail validation.
The synthetic fixture is a complete input example. Per-CVE invalid score bodies
become unknown with detailed causes, allowing independent valid KEV evidence to
continue supporting P1.

| Signal | Requirement |
| --- | --- |
| Confirmed CISA evidence | Valid catalog inclusion or validated entry; no automatic expiry |
| Current observed absence | Nonempty, complete, validated full catalog captured within 48 hours |
| EPSS | Probability from 0 to 1; score date 0–2 UTC calendar days old |
| CVSS | Valid preferred metric; NVD capture within 168 hours; no future source timestamps |
| Threat Velocity promotion | Every existing coverage, freshness, rise, and reviewed-model gate passes |

Freshness boundaries are inclusive. EPSS zero is valid, percentile does not drive
probability thresholds, and missing percentile metadata stays null. Preferred
CVSS uses newest version, then Primary, then source/vector order. Severe means
HIGH/CRITICAL categorically, without pooling numerical scores across versions.
Rejected metrics cannot support severity rules. Stale scores remain visible with
`usable=false` or a quality classification. A malformed current record does not
silently fall back to a more favorable older score.

Committed daily KEV snapshots reconstruct full catalogs, even if a later source
in that run failed. Retained manual KEV rows prove historical inclusion, not
current coverage. Historical NVD snapshots and latest enrichment rows are read;
the newest available capture is evaluated. Database export availability is
conservatively set to export completion, so legacy timestamps and overwritten
EPSS/latest rows cannot establish earlier availability. Keep frozen exports for
later replay; backdated evaluation cannot recover missing versions.

Use `--model-regimes REVIEWED_REGISTRY_JSON` only after an evidence-backed review
following the Threat Velocity guide. The default empty registry permits rates
but disables promotion. Invented demo declarations must never authorize real data.

## Audited source corrections and limits

Omission from a newer catalog alone never withdraws known exploitation evidence.
A `kev_withdrawals` entry in frozen input identifies `correction_id`, `cve_id`,
specific positive `evidence_ids`, `reviewed_at`, `reviewer`, `rationale`, and
`source_url`. Catalog positives use `CATALOG_EVIDENCE_ID:CVE_ID`; entry positives
use their wrapper ID, both recorded under `values.kev.evidence`. Each withdrawn ID
must be known and captured by the correction time. A correction is only usable
after its review time, and only removes explicitly identified evidence. Independent
or newly captured positive evidence still supports P1. Lowering a prior P1 also
requires a separate matching downgrade acknowledgement. Preserve corrections in
subsequent frozen inputs as long as the corresponding source evidence is present.

The database cohort is historically KEV-based. Existing comparison studies remain
separate; their non-KEV CVEs are not silently incorporated. Public comparisons and
learned models need the next roadmap task: immutable daily tracking of a defined
NVD non-KEV cohort. The engine currently loads stored history into memory;
large-scale incremental state, authorization, dashboard integration, and prospective
threshold validation remain separate work. See
[decision 013](decisions/013-baseline-priority-engine.md) for implementation choices.
