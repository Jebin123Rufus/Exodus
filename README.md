# Exodus

**Exodus** is an AI-native Static Application Security Analysis (SAST) platform that analyzes entire software repositories to identify application-level security vulnerabilities and generate actionable remediation reports. It combines semantic code understanding, AI-driven security reasoning, and repository-wide evidence correlation into a unified security analysis pipeline.

Instead of relying solely on rule-based pattern matching, Exodus extracts security evidence from source code, correlates it across the repository, and produces comprehensive security findings with developer-focused remediation and executive-ready reports.

---

# Problem Statement

Modern software systems are becoming increasingly complex, and the rapid adoption of AI-assisted software development has accelerated code production. Existing static analysis solutions often struggle to understand application context, producing fragmented findings and overwhelming developers with false positives. There is a growing need for an intelligent security analysis platform capable of understanding source code semantically and delivering accurate, contextual, and actionable security insights.

---

# Features

* GitHub OAuth authentication
* Repository ingestion and analysis
* Multi-language source code support
* Semantic code chunking
* AI-powered security evidence extraction
* Repository-wide evidence correlation
* Multi-stage security reasoning pipeline
* Enterprise-grade security report generation
* Interactive dashboard with findings visualization
* Developer-focused remediation guidance
* Executive-ready security summaries

---

# Analysis Pipeline

Exodus follows a four-stage AI pipeline.

```text
GitHub Repository
        │
        ▼
Phase 1
Repository Extraction & Semantic Chunking
        │
        ▼
Phase 2
Security Evidence Extraction
        │
        ▼
Phase 3
Repository-wide Security Correlation
        │
        ▼
Phase 4
Security Advisor & Report Generation
        │
        ▼
Interactive Dashboard & Reports
```

---

# Pipeline Overview

## Phase 1 — Repository Extraction & Semantic Chunking

* Repository ingestion
* Language detection
* Semantic chunk generation
* Repository metadata extraction
* File coverage validation

---

## Phase 2 — Security Evidence Extraction

The evidence extraction engine analyzes every semantic chunk and extracts security-relevant artifacts, including:

* Input sources
* Authentication components
* Authorization checks
* Database operations
* File system operations
* Cryptographic APIs
* Secrets
* Session management
* Serialization
* XML processing
* Network operations
* Framework components
* AI/LLM integrations
* Configuration artifacts
* Security relationships

The extracted evidence is persisted in MongoDB as structured nodes and relationships.

---

## Phase 3 — Repository Security Correlation

The correlation engine reasons over extracted evidence to identify application-level security findings across the repository.

Supported categories include:

* Injection Vulnerabilities
* Cross-Site Scripting (XSS)
* Cross-Site Request Forgery (CSRF)
* Authentication Weaknesses
* Authorization & Access Control
* Session Management
* Cryptographic Weaknesses
* Secrets & Credential Exposure
* Sensitive Data Exposure
* Server-Side Request Forgery (SSRF)
* XML & XXE
* Path Traversal
* File Upload & File Processing
* Insecure Deserialization
* API Security
* Business Logic Vulnerabilities
* Race Conditions & TOCTOU
* Input Validation
* Output Encoding
* HTTP Header Security
* Logging & Error Handling
* Security Misconfiguration
* Dependency & Package Security
* Unsafe Framework/API Usage
* Memory Safety
* Integer & Arithmetic Issues
* Regular Expression (ReDoS)
* Resource Exhaustion / DoS
* Open Redirect
* WebSocket Security
* GraphQL Security
* gRPC Security
* OAuth / OIDC / SAML / JWT
* AI & LLM Security
* Privacy & Compliance Issues
* Insecure Design Patterns
* Hidden Attack Surface
* Deprecated Language Features
* Code Quality Issues with Security Impact
* Framework-Specific Vulnerabilities

---

## Phase 4 — Security Advisor

The Security Advisor transforms validated findings into enterprise-grade reports by generating:

* Executive Summary
* Technical Summary
* Root Cause Analysis
* Business Impact
* Technical Impact
* Evidence Chain
* Attack Path
* Risk Assessment
* Priority Score
* Secure Code Fixes
* Framework-specific Recommendations
* Secure Coding Guidance
* Prevention Strategies
* Standards Mapping (CWE, OWASP, ASVS, CAPEC, MITRE ATT&CK, CERT)
* References

---

# Technology Stack

## Frontend

* React
* Vite
* CSS

## Backend

* Node.js
* Express.js

## Database

* MongoDB

## Authentication

* GitHub OAuth
* Passport.js
* express-session

## AI Services

* Groq SDK
* Multi-stage LLM pipeline

---

# Project Architecture

```text
client/
│
├── src/
├── public/
└── vite.config.js

backend/
│
├── src/
│   ├── chunking/
│   ├── evidence/
│   ├── correlation/
│   ├── advisor/
│   ├── routes/
│   ├── services/
│   └── utils/
│
├── server.js
└── test/
```

---

# Installation

## Clone the repository

```bash
git clone <repository-url>
cd Exodus
```

## Install dependencies

Backend

```bash
cd backend
npm install
```

Frontend

```bash
cd ../client
npm install
```

---

# Environment Variables

Create a `.env` file inside the `backend` directory.

```env
PORT=5000

FRONTEND_URL=http://localhost:5173
BASE_URL=http://localhost:5000

MONGODB_URI=mongodb://127.0.0.1:27017/exodus

SESSION_SECRET=your-session-secret

GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret

GROQ_API_KEY=your-phase-1-key
GROQ_LLAMA_PHASE_2=your-phase-2-key
GROQ_LLAMA_PHASE_3=your-phase-3-key
GROQ_LLAMA_PHASE_4=your-phase-4-key
```

---

# Running the Project

Run both frontend and backend

```bash
cd client
npm run dev
```

Or separately

Backend

```bash
cd backend
npm run dev
```

Frontend

```bash
cd client
npm run client
```

---

# Analysis Workflow

```text
GitHub Login
        │
        ▼
Repository Selection
        │
        ▼
Repository Extraction
        │
        ▼
Semantic Chunking
        │
        ▼
Security Evidence Extraction
        │
        ▼
Repository-wide Correlation
        │
        ▼
Security Findings
        │
        ▼
Security Advisor
        │
        ▼
Interactive Dashboard
        │
        ▼
Enterprise Security Report
```

---

# Output

Exodus generates:

* Executive Security Report
* Developer Security Report
* Interactive Dashboard
* Risk Assessment
* Repository Statistics
* Vulnerability Breakdown
* Actionable Remediation Guidance

---

# Future Roadmap

* Repository comparison across scans
* Incremental analysis
* Pull Request scanning
* CI/CD integration
* GitHub Checks integration
* Team workspaces
* Custom organization policies
* AI-assisted remediation patches
* Historical security trends
* Multi-repository portfolio analysis

---

# Disclaimer

Exodus is an AI-assisted static application security analysis platform. Findings should be reviewed by developers or security professionals before remediation decisions are made. The platform is intended to assist secure software development by providing contextual, explainable, and actionable security insights.
