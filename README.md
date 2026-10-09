# ThreatPulse

**Cyber Threat Intelligence Analytics & Vulnerability Prioritization Platform**

ThreatPulse is an open-source cybersecurity analytics project designed to collect, normalize, analyze, and visualize vulnerability and threat intelligence data.

The goal of the project is to help answer a practical security question:

> **Out of thousands of vulnerabilities and threat indicators, which ones deserve attention first?**

ThreatPulse combines vulnerability severity, exploitation probability, known exploitation activity, threat intelligence, and eventually organizational asset context to support more informed cybersecurity prioritization.

---

## Project Status

🚧 **Active Development — v0.1**

ThreatPulse is currently being developed as a long-term cybersecurity and data analytics project.

The initial development focus is:

- Automated vulnerability intelligence collection
- Data normalization and storage
- Vulnerability analytics
- Exploitation-based prioritization
- Interactive dashboards
- Containerized deployment

Future versions will introduce IOC intelligence, workflow automation, asset-aware prioritization, and automated security reporting.

The baseline prioritization policy and ML study design are documented. The
priority engine and locally trained ML models are still planned. Public-facing
results will include source dates, coverage, decision reasons, and model limits.

---

## Project Goals

ThreatPulse is being developed to explore the intersection of:

- Cybersecurity
- Threat intelligence
- Vulnerability management
- Data analytics
- Data engineering
- Security automation
- API integration
- Containerization

The project aims to transform large volumes of public cybersecurity data into information that security analysts can use to make prioritization decisions.

---

## Core Research Question

Traditional vulnerability management frequently relies heavily on vulnerability severity.

ThreatPulse explores a broader question:

> **How does vulnerability prioritization change when severity is combined with exploitation probability, known exploitation, historical trends, and organizational context?**

The project will analyze relationships between:

- CVSS severity
- EPSS exploitation probability
- CISA Known Exploited Vulnerability status
- Vulnerability characteristics
- Exploitation trends
- Asset exposure
- Asset criticality

---

## Planned Architecture

```text
                         ThreatPulse

        ┌─────────────────────────────────────┐
        │            Data Sources             │
        │                                     │
        │   NVD       EPSS       CISA KEV     │
        │   IoCs      Threat Intelligence     │
        └─────────────────┬───────────────────┘
                          │
                          ▼
                ┌──────────────────┐
                │ Data Ingestion   │
                │ Python / APIs    │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Data Validation  │
                │ & Normalization  │
                └────────┬─────────┘
                         │
                         ▼
                  ┌────────────┐
                  │ PostgreSQL │
                  └─────┬──────┘
                        │
            ┌───────────┴────────────┐
            │                        │
            ▼                        ▼
   ┌─────────────────┐      ┌─────────────────┐
   │ Python Analytics│      │ Priority Engine │
   │ Pandas / SciPy  │      │ Risk Logic      │
   └────────┬────────┘      └────────┬────────┘
            │                        │
            └────────────┬───────────┘
                         ▼
               ┌───────────────────┐
               │ ThreatPulse      │
               │ Dashboard        │
               └────────┬──────────┘
                        │
                        ▼
               ┌───────────────────┐
               │ n8n Automation    │
               │ Alerts / Reports  │
               └───────────────────┘
```

---

## Planned Technology Stack

### Cybersecurity Data

- National Vulnerability Database (NVD)
- CISA Known Exploited Vulnerabilities (KEV)
- Exploit Prediction Scoring System (EPSS)
- Public threat intelligence and IOC sources

### Data Engineering

- Python
- REST APIs
- JSON
- PostgreSQL
- SQL
- Pandas

### Analytics

- Pandas
- NumPy
- SciPy
- Scikit-learn
- Jupyter

Scikit-learn is planned for logistic regression and gradient boosting experiments
on longitudinal KEV/non-KEV data. It is not yet a project dependency. Its role,
prediction target, evaluation, and adoption criteria are defined in
[the ML study design](docs/ml-study-design.md).

### Visualization

- Streamlit
- Matplotlib
- Interactive analytics dashboards

### Automation

- n8n
- Scheduled ingestion workflows
- Security alerts
- Automated reporting

### Infrastructure

- Docker
- Docker Compose
- GitHub

---

## Planned Features

### Vulnerability Intelligence

ThreatPulse will collect and correlate vulnerability information including:

- CVE identifiers
- CVSS scores
- Vulnerability severity
- Attack vectors
- EPSS probability
- EPSS percentile
- CISA KEV status
- Vulnerability age
- Vendor and product information

---

### Vulnerability Analytics

The analytics layer will investigate questions such as:

- How do EPSS distributions differ between KEV and non-KEV vulnerabilities?
- How strongly does CVSS severity correspond with exploitation probability?
- Which vulnerability characteristics appear most frequently among known exploited vulnerabilities?
- Which vendors and products appear most frequently in exploitation datasets?
- How does exploitation probability change over time?

---

### Threat Velocity

ThreatPulse tracks dated EPSS observations and calculates changes in exploitation
probability over time.

Example:

```text
CVE-XXXX-XXXX

EPSS

Day 1      4%
Day 2      8%
Day 3     21%
Day 5     49%
Day 7     81%

Threat Velocity: RISING (illustrative)
```

The calculation reports EPSS change in percentage points per day, with coverage,
freshness, and model-regime comparability checks. The example assumes those
checks pass. See [the Threat Velocity guide](docs/threat-velocity.md) for the
read-only command, model-review requirements, and reproducible outputs.

---

### Threat Prioritization

The baseline will assign explainable intelligence review tiers using ordered
rules over known exploitation, EPSS probability, CVSS severity, and qualified
historical trends. Later asset-aware analysis will add applicability, internet
exposure, and business criticality to support a remediation queue.

[The prioritization methodology](docs/prioritization-methodology.md) defines
transparent baseline tiers, data-quality rules, provisional trend promotion,
and worked examples. A future learned score will be evaluated against this
baseline and EPSS before advisory integration. KEV inclusion predictions will
be labeled separately from EPSS exploitation probabilities.

---

## Future IOC Intelligence

Future versions of ThreatPulse will include Indicator of Compromise analytics.

Supported indicator types may include:

- IPv4 / IPv6 addresses
- Domains
- URLs
- SHA256 hashes
- Malware families

Planned analytics include:

- IOC activity over time
- Malware-family trends
- IOC confidence analysis
- Infrastructure trends
- IOC freshness
- Threat intelligence enrichment

---

## Security Automation

n8n will eventually orchestrate ThreatPulse workflows.

Example:

```text
Scheduled Trigger
       │
       ▼
Retrieve Security Data
       │
       ▼
Validate & Normalize
       │
       ▼
Store in PostgreSQL
       │
       ▼
Run Analytics
       │
       ▼
Recalculate Priorities
       │
       ▼
Material Change?
     /       \
   NO         YES
   │           │
   END       Alert
```

Potential automation outputs include:

- Email alerts
- Webhooks
- Daily threat summaries
- Vulnerability change notifications
- Security reports

---

## Future Asset-Aware Analysis

A later stage of ThreatPulse will allow organizational asset information to be correlated with vulnerability intelligence.

Example input:

```csv
hostname,product,version,criticality,internet_facing
WEB01,Apache HTTP Server,2.4.49,critical,true
DB01,PostgreSQL,14,critical,false
CLIENT01,Windows 11,23H2,medium,false
```

ThreatPulse would use this context to move from:

> "These vulnerabilities are dangerous."

to:

> **"These vulnerabilities are most relevant to your environment."**

The eventual goal is to produce an actionable remediation queue based on vulnerability intelligence and organizational context.

---

## Development Roadmap

### Phase 1 — Foundation

- [ ] Define architecture
- [x] Configure Docker Compose
- [x] Deploy PostgreSQL
- [x] Create database schema
- [x] Configure Python development environment

### Phase 2 — Vulnerability Data Pipeline

- [x] Integrate NVD data
- [x] Integrate EPSS
- [x] Integrate CISA KEV
- [x] Normalize vulnerability records
- [x] Implement data validation
- [x] Store vulnerability history

### Phase 3 — Analytics

- [x] Exploratory data analysis
- [x] KEV vs. non-KEV comparison
- [x] CVSS vs. EPSS analysis
- [x] Vulnerability trend analysis
- [x] Statistical testing
- [x] Historical EPSS analysis

### Phase 4 — Prioritization

- [x] Develop prioritization methodology
- [x] Implement Threat Velocity
- [ ] Build prioritization engine
- [x] Document baseline policy assumptions and limitations

The methodology is a versioned design with provisional defaults. Threat Velocity
now provides quality-gated, reproducible signals; the baseline prioritization
engine is the next implementation task. See [the methodology](docs/prioritization-methodology.md)
and [Threat Velocity](docs/threat-velocity.md). The engine and risk validation
remain pending.

### Phase 4B — Machine Learning Research and Integration

- [x] Define the prediction target, dataset contract, and evaluation plan
- [ ] Track a defined NVD non-KEV cohort alongside KEV with immutable daily history
- [ ] Build versioned features available at prediction time and censored 30-day labels
- [ ] Train scikit-learn logistic regression and gradient boosting models
- [ ] Validate on later unseen CVEs against EPSS and baseline priority rules
- [ ] Evaluate calibration, missingness, subgroup performance, and incremental value
- [ ] Publish reproducible experiments, dataset examples, and model cards
- [ ] Integrate a validated advisory model with KEV overrides and baseline fallback
- [ ] Monitor drift, coverage, calibration, and model availability

Cohort collection can start after the study design, while baseline work proceeds.
Training depends on mature outcome labels; model adoption depends on held-out
evaluation and an implemented baseline engine. See [the ML study design](docs/ml-study-design.md).

### Phase 5 — Dashboard

- [x] Threat overview
- [x] Vulnerability explorer
- [x] CVE detail pages
- [x] KEV analytics
- [x] EPSS analytics
- [ ] Threat Velocity visualization
- [ ] Explain priority tiers with source freshness, coverage, and decision reasons
- [ ] Display validated model advice with its target, version, and limitations

### Phase 6 — Threat Intelligence

- [ ] IOC ingestion
- [ ] Malware-family tracking
- [ ] IOC normalization
- [ ] Threat intelligence analytics
- [ ] IOC dashboard

### Phase 7 — Automation

- [ ] Deploy n8n
- [x] Automate ingestion
- [ ] Build alert workflows
- [ ] Generate daily threat summaries

### Phase 8 — Asset-Aware Prioritization

- [ ] Asset inventory ingestion
- [ ] Product normalization
- [ ] CVE-to-asset correlation
- [ ] Asset criticality
- [ ] Exposure-aware prioritization
- [ ] Remediation queue

### Phase 9 — Public Release

- [ ] Public ThreatPulse dashboard
- [ ] Documentation
- [ ] Demo environment
- [ ] Architecture diagrams
- [ ] API documentation
- [ ] Project demonstration video
- [ ] Publish versioned policy examples and complete dataset/model reproduction guides
- [ ] Document source attribution, redistribution terms, and supported data/model scope
- [ ] Verify model cards, degraded-data behavior, and baseline fallback in the public demo

---

## Repository Structure

```text
threatpulse/

├── analytics/
│   └── notebooks/
│
├── dashboard/
│
├── database/
│   ├── migrations/
│   └── schema.sql
│
├── ingestion/
│   ├── nvd/
│   ├── epss/
│   ├── kev/
│   └── threat_intel/
│
├── scoring/
│
├── workflows/
│   └── n8n/
│
├── tests/
│
├── docs/
│
├── docker-compose.yml
├── .env.example
├── README.md
└── LICENSE
```

---

## Running ThreatPulse

The current command-line pipeline collects CISA KEV, stores it in PostgreSQL,
and enriches stored CVEs with EPSS and NVD data. Python 3.12, uv, Docker Engine,
and Docker Compose are required. See the [development guide](docs/development.md)
to configure the database password, `DATABASE_URL`, and optional `NVD_API_KEY`
securely before running ingestion.

```bash
git clone https://github.com/markinhohn/ThreatPulse.git
cd ThreatPulse
uv sync --locked
# Configure .env and export DATABASE_URL as described in the development guide.
docker compose up -d --wait db
uv run --locked python -m threatpulse.storage ingest-kev
uv run --locked python -m threatpulse.storage ingest-epss
uv run --locked python -m threatpulse.storage ingest-nvd
```

Ingestion creates or upgrades the schema automatically. Repeated runs update
existing data without duplicate CVEs; EPSS retains observations by score date.
Launch the initial dashboard after configuring `DATABASE_URL`:

```bash
uv run --locked streamlit run src/threatpulse/dashboard.py \
  --server.address=127.0.0.1 --server.port=8501 \
  --server.headless=true --browser.gatherUsageStats=false
```

The dashboard provides an overview, filtered vulnerability explorer, CVE
details with EPSS history, and dedicated KEV/EPSS descriptive analytics.
Run `uv run --locked python -m threatpulse.storage ingest-daily` for checkpointed
daily collection with KEV/NVD snapshots. See [scheduling and recovery](docs/scheduling.md)
for the systemd timer, retries, and run inspection.

Generate a reproducible exploratory report from the stored data:

```bash
uv run --locked python -m threatpulse.exploration --output data/exploration
```

Open `data/exploration/report.html` for coverage, CVSS/EPSS distributions,
version-specific associations, and historical EPSS changes. The export includes
CSV tables, SVG/PNG figures, and an offline replay dataset. See
[the analysis guide](docs/exploration.md) for dates, methods, and limitations.
Collect a defined NVD publication-window cohort and compare KEV/non-KEV
CVSS and same-date EPSS distributions with `python -m threatpulse.comparison`.
See [the comparison guide](docs/comparison.md) for collection, frozen study
storage, coverage, offline replay, and selection bias.
Generate snapshot and multi-date EPSS trends with
`python -m threatpulse.trends --output data/trends`. The report tracks observed
KEV membership changes, comparable preferred CVSS changes, calendar gaps,
matched EPSS changes, and a balanced EPSS panel. See
[the trend guide](docs/trends.md) for reproducible exports and limitations.
Run `python -m threatpulse.statistics --input SOURCE_JSON --output data/statistics`
for exploratory permutation tests, effect sizes, nominal bootstrap confidence
intervals, and Holm correction across the five planned endpoints. See
[the statistical guide](docs/statistical-testing.md) for sample requirements,
coverage, reproducible plans, and observational assumptions.
The [prioritization methodology](docs/prioritization-methodology.md) now specifies
baseline decisions and data-quality handling. Run
`python -m threatpulse.velocity --output data/velocity` for EPSS change rates,
coverage/freshness checks, audited model comparability, and offline replay.
See [the Threat Velocity guide](docs/threat-velocity.md). The baseline engine
is next. [The ML study design](docs/ml-study-design.md) defines the separate
data collection, training, validation, and advisory integration milestones.

---

## Data Ethics & Limitations

ThreatPulse is intended for defensive cybersecurity research, analytics, and vulnerability prioritization.

Threat intelligence and vulnerability data may contain incomplete, delayed, or inaccurate information.

ThreatPulse prioritization should therefore be treated as decision-support information rather than a replacement for:

- Security analyst judgment
- Vulnerability validation
- Asset-context analysis
- Risk assessment
- Vendor guidance

External data sources also maintain their own licensing, attribution, rate-limit, and commercial-use requirements.

---

## Project Motivation

Cybersecurity teams face an enormous amount of vulnerability and threat information.

A CVSS score can describe technical severity, but severity alone does not answer questions such as:

- Is the vulnerability being exploited?
- How likely is exploitation?
- Is exploitation activity increasing?
- Is the affected system exposed?
- Is the system critical to the organization?

ThreatPulse is an experiment in combining these signals into a more useful analytical view of cyber risk.

---

## Author

Cybersecurity | Threat Intelligence | Security Analytics | Detection & Incident Response

This project is being developed as part of an ongoing effort to combine cybersecurity engineering, data analytics, threat intelligence, and security automation into practical defensive-security tools.

---

## Disclaimer

ThreatPulse is an independent research and educational project.

It is not affiliated with or endorsed by any external intelligence provider, government agency, or scoring organization referenced by the project.
