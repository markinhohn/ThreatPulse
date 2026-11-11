# 014 — Immutable prospective cohort and KEV reference history

Status: implemented collection milestone. Features, labels, and training remain
separate roadmap tasks.

Freeze the complete census of a defined half-open UTC NVD publication interval,
spanning 1–120 completed days. An over-cap or inconsistent census fails rather
than returning a first-page sample. Persist its definition, source responses,
and normalized records. Keep every census member, including rejected records,
known current/historical KEV, unconfirmed exploitation conflicts, and missing
EPSS/CVSS. Record exclusions explicitly without selecting controls by scores.
Deduplicate CVEs globally across overlapping windows while retaining each
window's enrollment facts. Future datasets must still create one index sample
per eligible CVE, rather than one example per enrollment or daily observation.

Migration 6 creates a separate registry, cohorts, memberships, frozen run plans,
source observations, checkpoints, and HTTP request/response journal. It adds no
non-KEV CVEs to existing dashboard or frozen comparison tables. Row and truncate
triggers prevent ordinary updates/deletions of research evidence. Run/attempt
lifecycle state is mutable; old source attempts remain recorded. Administrators
can disable triggers, so this is not cryptographic identity or tamper proofing.

Collect an initial complete CISA catalog to discover reference CVEs, freeze the
request plan, collect EPSS and NVD, then collect a second complete CISA catalog.
The final validated availability time establishes enrollment's absence boundary.
Freeze historical positive IDs and proofs before that final fetch. Reference new
immutable observations or freeze legacy CISA records with source/capture/hash
provenance and conservatively bounded export availability. Replay/finalization after
an interruption uses those recorded facts, never later source evidence. Preserve
actual batch capture, HTTP receipt, validation availability, and source score
date separately. Availability records collection/validation completion; they do
not assert the transaction had already committed at that exact timestamp.
Feature-source commits precede the final CISA request. This milestone creates
no prediction boundary/sample, feature matrix, or outcome labels.

Daily monitoring freezes the whole registered population, including excluded
CVEs and retained/current KEV reference CVEs. Original membership does not change
when a CVE later enters KEV. Preserve all complete catalogs and explicit missing
responses; do not fabricate snapshots for failed/unattempted sources or missed
days. New KEV entries discovered after the plan are preserved immediately, with
feature collection starting on the next plan. Continue monitoring beyond 32 days;
retention/label maturity decisions belong to later workflows.

Use the same ingestion lock, validated source clients, NVD pacing/retries, and
atomic source checkpoint pattern as existing collection. Journal request starts
before sending, public successful response bytes before parsing, and sanitized
failure categories. Omit all headers and error response bodies. Resume committed
steps without overwriting versions; a later-day resume records actual EPSS
provider score dates and new availability. The common client pins each batch to
one provider date, separate from the nominal run date. No date option claims retrospective
KEV/NVD collection. A terminal success is idempotent.

Ship a separate optional daily systemd timer, read-only exports, deterministic
offline replay, source/code/package hashes, and coverage/gap summaries. These
summaries do not implement outcome censoring. Test real source clients over
mock HTTP, real isolated PostgreSQL, mutations, failures, interrupted recovery,
overlaps, exclusions, late inclusions, historical availability, and replay.
See [the operational guide](../longitudinal-tracking.md).
