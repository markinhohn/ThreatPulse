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

ThreatPulse will track changes in exploitation probability over time.

Example:

```text
CVE-XXXX-XXXX

EPSS

Day 1      4%
Day 3      8%
Day 5     21%
Day 7     49%
Day 9     81%

Threat Velocity: RAPIDLY INCREASING
```

This feature is intended to help identify vulnerabilities whose exploitation signals are changing rapidly rather than relying only on static scores.

---

### Threat Prioritization

ThreatPulse will develop a prioritization model using multiple security signals.

Potential factors include:

```text
Vulnerability Severity
        +
Exploitation Probability
        +
Known Exploitation
        +
Threat Velocity
        +
Internet Exposure
        +
Asset Criticality
        ↓
ThreatPulse Priority
```

The purpose is not to replace existing security scoring systems, but to provide additional context for vulnerability prioritization.

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
- [ ] Configure Docker Compose
- [ ] Deploy PostgreSQL
- [ ] Create database schema
- [ ] Configure Python development environment

### Phase 2 — Vulnerability Data Pipeline

- [ ] Integrate NVD data
- [ ] Integrate EPSS
- [ ] Integrate CISA KEV
- [ ] Normalize vulnerability records
- [ ] Implement data validation
- [ ] Store vulnerability history

### Phase 3 — Analytics

- [ ] Exploratory data analysis
- [ ] KEV vs. non-KEV comparison
- [ ] CVSS vs. EPSS analysis
- [ ] Vulnerability trend analysis
- [ ] Statistical testing
- [ ] Historical EPSS analysis

### Phase 4 — Prioritization

- [ ] Develop prioritization methodology
- [ ] Implement Threat Velocity
- [ ] Build prioritization engine
- [ ] Document model assumptions and limitations

### Phase 5 — Dashboard

- [ ] Threat overview
- [ ] Vulnerability explorer
- [ ] CVE detail pages
- [ ] KEV analytics
- [ ] EPSS analytics
- [ ] Threat Velocity visualization

### Phase 6 — Threat Intelligence

- [ ] IOC ingestion
- [ ] Malware-family tracking
- [ ] IOC normalization
- [ ] Threat intelligence analytics
- [ ] IOC dashboard

### Phase 7 — Automation

- [ ] Deploy n8n
- [ ] Automate ingestion
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

ThreatPulse is currently under active development.

The eventual goal is to launch the development environment with:

```bash
git clone https://github.com/<username>/threatpulse.git

cd threatpulse

docker compose up -d
```

Additional setup instructions will be added as development progresses.

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

**Tony Anselmy**

Cybersecurity | Threat Intelligence | Security Analytics | Detection & Incident Response

This project is being developed as part of an ongoing effort to combine cybersecurity engineering, data analytics, threat intelligence, and security automation into practical defensive-security tools.

---

## Disclaimer

ThreatPulse is an independent research and educational project.

It is not affiliated with or endorsed by any external intelligence provider, government agency, or scoring organization referenced by the project.
