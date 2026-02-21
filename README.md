# 🔒 PR Security Scanner

A comprehensive GitHub PR Security Scanner Bot that supports scanning **ALL file types** used in software development - from SQL syntax to configuration files to infrastructure-as-code - for security vulnerabilities, code smells, maintainability issues, and OWASP vulnerabilities.

## ✨ Features

### 📁 Comprehensive File Type Coverage

#### Database Files
- **SQL** (`.sql`) - MySQL, PostgreSQL, SQLite, SQL Server, Oracle
- **NoSQL** (`.mongo`, `.redis`, `.cql`)

#### Configuration Files
- **JSON** (`.json`, `.jsonc`)
- **YAML** (`.yml`, `.yaml`)
- **XML** (`.xml`, `.xsd`, `.wsdl`)
- **INI/Config** (`.ini`, `.cfg`, `.conf`, `.cnf`)
- **Properties** (`.properties`, `.env`)
- **TOML** (`.toml`)

#### Infrastructure as Code
- **Terraform** (`.tf`, `.tfvars`, `.hcl`)
- **Docker** (`Dockerfile`, `docker-compose.yml`)
- **Kubernetes** (YAML manifests)
- **CloudFormation** (`.json`, `.yaml`, `.template`)
- **Ansible** (playbooks)
- **Pulumi** (`.ts`, `.js`, `.py`, `.go`, `.cs`)

#### Build & Dependency Files
- **JavaScript/Node.js** (`package.json`, `package-lock.json`, `yarn.lock`)
- **Python** (`requirements.txt`, `Pipfile`, `pyproject.toml`)
- **Java** (`pom.xml`, `build.gradle`, `gradle.lockfile`)
- **Go** (`go.mod`, `go.sum`)
- **Rust** (`Cargo.toml`, `Cargo.lock`)
- **Ruby** (`Gemfile`, `Gemfile.lock`)
- **PHP** (`composer.json`, `composer.lock`)
- **Make/CMake** (`Makefile`, `CMakeLists.txt`)

#### Data Files
- **CSV/TSV** (`.csv`, `.tsv`)
- **JSON Lines** (`.jsonl`, `.ndjson`)

#### Markup Files
- **HTML** (`.html`, `.htm`)
- **Markdown** (`.md`, `.markdown`, `.mdx`)

### 🔐 Security Detection Capabilities

#### OWASP Top 10 2021 Coverage
- **A01:2021** - Broken Access Control
- **A02:2021** - Cryptographic Failures
- **A03:2021** - Injection (SQL, NoSQL, Command, LDAP, XPath, XXE)
- **A04:2021** - Insecure Design
- **A05:2021** - Security Misconfiguration
- **A06:2021** - Vulnerable and Outdated Components
- **A07:2021** - Identification and Authentication Failures
- **A08:2021** - Software and Data Integrity Failures
- **A09:2021** - Security Logging and Monitoring Failures
- **A10:2021** - Server-Side Request Forgery (SSRF)

#### Secret Detection
- AWS Access Keys & Secret Keys
- Azure Service Principals & Storage Keys
- GCP API Keys & Service Accounts
- Database Connection Strings (MongoDB, MySQL, PostgreSQL, Redis)
- Private Keys (RSA, SSH, PEM, PGP)
- Authentication Tokens (JWT, OAuth, Bearer)
- GitHub/GitLab/Bitbucket Tokens
- Slack Tokens & Webhooks
- API Keys (Stripe, Twilio, SendGrid)
- Generic secrets and credentials

#### Infrastructure Security
- **Terraform**: Overly permissive security groups, public S3 buckets, unencrypted RDS
- **Docker**: Privileged containers, latest tags, hardcoded secrets, insecure base images
- **Kubernetes**: Privileged pods, missing security contexts, host namespace sharing
- **CloudFormation**: Unencrypted resources, exposed databases

#### Dependency Vulnerabilities
- Detects known vulnerable package versions
- CVE tracking for common vulnerabilities
- Version pinning recommendations

### 🤖 AI-Powered Analysis (Optional)

The scanner supports **AI-powered security analysis** using large language models to provide intelligent vulnerability detection beyond traditional static analysis.

#### Supported AI Providers
- **OpenAI** (GPT-4, GPT-3.5 Turbo)
- **Azure OpenAI** (Enterprise deployment)
- **Anthropic** (Claude 3 Opus, Claude 3 Sonnet)
- **Google AI** (Gemini Pro)
- **Ollama** (Self-hosted models like Llama 2)

#### AI Features
- Intelligent vulnerability detection using LLMs
- Context-aware security analysis
- Automatic remediation suggestions
- Reduced false positives through AI understanding
- Cost tracking and budget management
- Response caching for optimization
- Fallback to static rules if AI fails

## 🚀 Usage

### GitHub Actions

```yaml
name: Security Scan

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
      checks: write

    steps:
      - uses: actions/checkout@v4

      - name: Run PR Security Scanner
        uses: your-org/pr-security-scanner@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: 'high'
          enable-owasp: 'true'
          enable-secrets: 'true'
          # Enable AI analysis
          enable-ai-analysis: 'true'
          ai-config-path: '.ai-config.json'
          ai-cost-limit: '50'
```

### Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github-token` | GitHub token for PR comments | Yes | `${{ github.token }}` |
| `scan-directory` | Directory to scan | No | `.` |
| `fail-on` | Fail on severity level | No | `high` |
| `include-extensions` | Comma-separated extensions to include | No | (all) |
| `exclude-extensions` | Comma-separated extensions to exclude | No | (none) |
| `exclude-paths` | Comma-separated paths to exclude | No | `node_modules,dist,build` |
| `enable-owasp` | Enable OWASP Top 10 detection | No | `true` |
| `enable-secrets` | Enable secret detection | No | `true` |
| `output-format` | Output format (json, sarif, markdown) | No | `markdown` |
| `verbose` | Enable verbose logging | No | `false` |
| `enable-ai-analysis` | Enable AI-powered security analysis | No | `false` |
| `ai-provider` | AI provider name to use | No | `` |
| `ai-config-path` | Path to AI configuration file | No | `.ai-config.json` |
| `ai-batch-size` | Files to analyze in parallel with AI | No | `5` |
| `ai-max-concurrency` | Maximum concurrent AI requests | No | `3` |
| `ai-cost-limit` | Maximum spending per scan (USD) | No | `50` |
| `ai-cache-results` | Cache AI responses to reduce costs | No | `true` |

### AI Configuration

To enable AI-powered analysis, create a configuration file (e.g., `.ai-config.json`) with your provider settings:

```json
{
  "ai": {
    "enabled": true,
    "defaultProvider": "openai-gpt4",
    "providers": [
      {
        "type": "openai",
        "name": "openai-gpt4",
        "enabled": true,
        "apiKey": "${{ secrets.OPENAI_API_KEY }}",
        "model": "gpt-4-turbo-preview",
        "maxTokens": 4000,
        "temperature": 0.1,
        "costTracking": {
          "enabled": true,
          "budgetLimit": 100
        }
      }
    ],
    "fallbackToStaticRules": true,
    "batchSize": 5,
    "maxConcurrency": 3,
    "cacheResults": true,
    "cacheTtl": 3600
  }
}
```

Then reference it in your workflow:

```yaml
- name: Run PR Security Scanner
  uses: your-org/pr-security-scanner@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    enable-ai-analysis: 'true'
    ai-config-path: '.ai-config.json'
    ai-cost-limit: '50'
```

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of security findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high findings |
| `medium-count` | Number of medium findings |
| `low-count` | Number of low findings |
| `report-path` | Path to the generated report |

## 📊 Reports

The scanner generates three report formats:

1. **Markdown Report** (`security-report.md`) - Human-readable format
2. **JSON Report** (`security-report.json`) - Machine-readable format
3. **SARIF Report** (`security-report.sarif`) - GitHub-compatible format

## 🎛️ Settings Management Interface

The scanner includes a built-in web interface for configuring AI providers and viewing usage statistics:

### Starting the Server

```bash
npm run start-server
```

The server will start on `http://localhost:3000` and provides:

- **AI Provider Management** - Add, configure, and test AI providers
- **Usage Analytics** - View token usage, costs, and performance metrics
- **Cost Tracking** - Monitor AI spending with budget limits
- **Cache Management** - Clear AI response cache
- **Configuration Export** - Save/load configuration files

### Features

- **Real-time Validation** - Test provider configurations before saving
- **Usage Dashboards** - Visual charts of AI usage and costs
- **Provider Status** - Monitor which providers are active and healthy
- **Cost Alerts** - Get notified when approaching budget limits
- **Configuration Backup** - Export/import settings as JSON

### API Endpoints

The web interface uses a REST API:

- `GET /api/ai/settings` - Get AI configuration
- `POST /api/ai/providers` - Add new provider
- `GET /api/ai/usage` - Get usage statistics
- `GET /api/ai/costs` - Get cost breakdown
- `DELETE /api/ai/cache` - Clear cache

## 🛠️ Development

### Prerequisites

- Node.js 20+
- npm or yarn

### Setup

```bash
# Clone the repository
git clone https://github.com/your-org/pr-security-scanner.git
cd pr-security-scanner

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test
```

### Project Structure

```
pr-security-scanner/
├── src/
│   ├── core/
│   │   ├── scanner-engine.ts    # Main scanning engine
│   │   ├── file-detector.ts     # File type detection
│   │   ├── github-integration.ts # GitHub PR integration
│   │   └── file-types.ts        # File type definitions
│   ├── scanners/
│   │   ├── sql/                 # SQL scanner
│   │   ├── config/              # JSON/YAML/XML/INI scanner
│   │   ├── infrastructure/      # Terraform/Docker/K8s scanner
│   │   ├── build/               # Package file scanner
│   │   ├── markup/              # HTML/Markdown scanner
│   │   └── data/                # CSV/JSONL scanner
│   ├── rules/
│   │   ├── owasp/               # OWASP Top 10 rules
│   │   ├── sql/                 # SQL injection patterns
│   │   ├── secrets/             # Secret detection patterns
│   │   └── infrastructure/      # IaC security rules
│   ├── types/                   # TypeScript types
│   └── index.ts                 # Main entry point
├── action.yml                   # GitHub Action definition
└── README.md                    # This file
```

## 🔒 Security Considerations

- The scanner detects potential security issues but cannot guarantee complete security
- False positives may occur - review findings carefully
- The scanner itself should be regularly updated
- Sensitive findings in logs are masked automatically
- Report artifacts should be protected appropriately

## 📄 License

MIT License - see [LICENSE](LICENSE) for details

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🙏 Acknowledgments

- OWASP Foundation for the Top 10 project
- Security community for best practices and patterns
- GitHub for Actions and security features
