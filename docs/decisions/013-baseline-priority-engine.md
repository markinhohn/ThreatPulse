# 013 — Explainable, replayable baseline prioritization

Status: implemented.

Apply policy v0.1's ordered rules to validated public-source evidence. Export
P1–P4, UNDETERMINED, and OUT_OF_SCOPE as separate intelligence-review queues,
with candidate/effective tiers, reasons, quality flags, provenance, and exact
decision/policy/input identifiers. These are provisional review priorities,
not calibrated risk scores or remediation deadlines. No local ML is required.

Confirmed historical CISA evidence does not expire when a later catalog omits a
CVE. Full committed daily catalogs establish current observed membership/absence;
retained individual rows establish positive historical evidence only. Unknown
catalog coverage prohibits P4. Rejected records cannot supply technical severity;
contradictory exploitation evidence and severe CVSS with unknown EPSS require
focused review. Invalid score bodies become unknown without discarding valid KEV
evidence. The existing Threat Velocity contract controls P3-to-P2 promotion.

Keep the previous ranked tier when new evidence proposes a weaker tier or an
unranked state. Require a named, dated, reasoned review bound to the policy hash,
input fingerprint, exact previous decision, and candidate. Carry positive KEV
evidence and missing prior-cohort CVEs into subsequent decisions. Audited source
corrections withdraw explicitly identified positive evidence; a separate matching
downgrade acknowledgement is still needed to lower a prior effective tier.

Read PostgreSQL in REPEATABLE READ, READ ONLY and reuse existing historical
snapshots. Freeze database evidence conservatively as available at export
completion; overwritten rows cannot reconstruct earlier versions. Priority and
review state lives in explicit versioned report files, avoiding a schema migration
before a storage/authorization workflow is defined. Repeated evaluations must
carry the previous analysis file. Reviews are trusted operator audit records,
not authenticated identities or signatures; checksums detect unintended changes.

Allow a later decision time on frozen inputs so a subsequent reviewer can approve
a concrete candidate. Never change source capture/availability times; re-evaluate
freshness and invalidate reviews when the input state or candidate changes.
Emit standalone HTML, complete JSON/CSV, frozen source/policy, and file/code/package
checksums. Require a new output directory. Ship a synthetic demo covering every
queue and test the documented scenarios, boundary/availability cases, correction
and review safeguards, read-only database snapshots, and deterministic replay.

See [the guide](../prioritization.md). Immutable non-KEV cohort tracking is next;
prospective validation, dashboard integration, and advisory local ML remain
separate roadmap milestones.
