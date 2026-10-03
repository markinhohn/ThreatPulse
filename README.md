# ThreatPulse

**ThreatPulse** is a cybersecurity threat intelligence and analytics platform designed to collect, normalize, analyze, and visualize Indicators of Compromise (IoCs) from multiple threat intelligence sources.

The project combines **cybersecurity, data analytics, APIs, automation, and containerized infrastructure** to explore how threat intelligence can be transformed from raw indicators into actionable security insights.

> 🚧 ThreatPulse is currently under active development.

---

## 🎯 Project Goals

ThreatPulse is being built to:

- Collect threat intelligence from public and commercial APIs
- Normalize IoCs from different data sources
- Store and enrich indicators for analysis
- Identify patterns across IP addresses, domains, URLs, hashes, and other indicators
- Visualize threat activity through dashboards
- Automate enrichment and analysis workflows
- Explore practical applications of threat intelligence for SOC and detection engineering workflows

---

## 🏗️ Planned Architecture

```text
Threat Intelligence APIs
        │
        ▼
   Data Collectors
      Python
        │
        ▼
 IOC Normalization
        │
        ▼
   Data Storage
    PostgreSQL
        │
   ┌────┴─────┐
   ▼          ▼
Analytics   Enrichment
   │          │
   └────┬─────┘
        ▼
     Dashboard
        │
        ▼
 Automation / n8n
```

---

## 🧰 Technology Stack

### Cybersecurity
- Threat Intelligence
- Indicators of Compromise (IoCs)
- IOC enrichment
- MITRE ATT&CK
- Security analytics

### Development & Data
- Python
- REST APIs
- SQL
- PostgreSQL
- Pandas

### Infrastructure
- Docker
- Docker Compose
- Git / GitHub

### Automation & Visualization
- n8n
- Dashboarding / data visualization

Additional technologies will be incorporated as the project develops.

---

## 📁 Project Structure

```text
ThreatPulse/
│
├── README.md
├── .gitignore
├── .env.example
├── docker-compose.yml
├── requirements.txt
│
├── src/
│   ├── collectors/
│   ├── processing/
│   ├── enrichment/
│   └── analytics/
│
├── dashboard/
├── automation/
├── docs/
├── tests/
└── sample-data/
```

The structure will evolve as new components are implemented.

---

## 🔄 Planned Data Pipeline

A typical ThreatPulse workflow will follow:

```text
Collect → Normalize → Enrich → Store → Analyze → Visualize → Automate
```

For example:

```text
Threat Feed
    ↓
Retrieve malicious IP
    ↓
Normalize indicator
    ↓
Add metadata
    ↓
Store in database
    ↓
Correlate with other sources
    ↓
Calculate analytics
    ↓
Display on dashboard
```

---

## 🔌 Planned Data Sources

Potential integrations include:

- AlienVault OTX
- VirusTotal
- AbuseIPDB
- URLhaus
- ThreatFox
- CISA threat intelligence sources

API integrations will be added incrementally as the project develops.

---

## 🐳 Docker

ThreatPulse will use Docker to provide a reproducible development and deployment environment.

Planned services include:

```text
collector
database
dashboard
automation
```

The objective is to allow the complete ThreatPulse environment to eventually be launched using:

```bash
docker compose up -d
```

---

## 🗺️ Development Roadmap

### Phase 1 — Foundation

- [ ] Define project architecture
- [ ] Create Python project structure
- [ ] Configure environment variables
- [ ] Configure Docker environment
- [ ] Deploy PostgreSQL database

### Phase 2 — Threat Intelligence Collection

- [ ] Integrate first threat intelligence API
- [ ] Build IOC collector
- [ ] Create common IOC data model
- [ ] Normalize API responses
- [ ] Store indicators in PostgreSQL

### Phase 3 — Enrichment & Analytics

- [ ] Add multiple threat intelligence sources
- [ ] Correlate indicators across sources
- [ ] Add enrichment workflows
- [ ] Develop threat scoring logic
- [ ] Perform IOC trend analysis

### Phase 4 — Visualization

- [ ] Create interactive dashboard
- [ ] Visualize IOC types and trends
- [ ] Display threat source statistics
- [ ] Create indicator investigation views

### Phase 5 — Automation

- [ ] Integrate n8n
- [ ] Automate IOC enrichment
- [ ] Create alerting workflows
- [ ] Automate scheduled threat-feed ingestion

### Phase 6 — Security Engineering

- [ ] Map relevant intelligence to MITRE ATT&CK
- [ ] Explore SIEM integrations
- [ ] Generate detection-useful outputs
- [ ] Document threat hunting use cases

---

## 🔐 Security

API keys and credentials are **not stored in the repository**.

Local credentials should be stored in:

```text
.env
```

A template will be maintained as:

```text
.env.example
```

Never commit API keys, passwords, tokens, or other secrets to GitHub.

---

## 📚 Project Motivation

Security teams consume large amounts of threat intelligence from independent sources. Those sources often use different formats, confidence levels, metadata, and terminology.

ThreatPulse explores how a unified pipeline can transform disparate threat intelligence into structured data that can be analyzed, correlated, visualized, and ultimately used to support security operations.

The project also serves as a hands-on environment for developing skills across:

- cybersecurity engineering
- threat intelligence
- detection engineering
- Python
- PowerShell
- data analytics
- APIs
- SQL
- Docker
- workflow automation

---

## 📈 Project Status

**Current Stage:** Initial development

ThreatPulse is being developed iteratively. Features, architecture documentation, screenshots, analytics, and deployment instructions will be added as components become functional.

---

## 📄 License

A license will be selected as the project matures.
