import { SecretPattern } from '../../types';

export const SECRET_PATTERNS: SecretPattern[] = [
  // API Keys and Tokens
  {
    name: 'AWS Access Key ID',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    category: 'cloud-credentials',
    description: 'AWS Access Key ID detected'
  },
  {
    name: 'AWS Secret Access Key',
    pattern: /[0-9a-zA-Z/+]{40}/g,
    severity: 'critical',
    category: 'cloud-credentials',
    description: 'Potential AWS Secret Access Key detected'
  },
  {
    name: 'Azure Storage Account Key',
    pattern: /AccountKey=[a-zA-Z0-9+/=]{88}/gi,
    severity: 'critical',
    category: 'cloud-credentials',
    description: 'Azure Storage Account Key detected'
  },
  {
    name: 'Azure Service Principal',
    pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    severity: 'high',
    category: 'cloud-credentials',
    description: 'Potential Azure Service Principal GUID detected'
  },
  {
    name: 'GCP API Key',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    severity: 'critical',
    category: 'cloud-credentials',
    description: 'Google Cloud Platform API Key detected'
  },
  {
    name: 'GCP Service Account',
    pattern: /[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com/gi,
    severity: 'medium',
    category: 'cloud-credentials',
    description: 'GCP Service Account email detected'
  },

  // Database Credentials
  {
    name: 'Database Connection String',
    pattern: /(mongodb(\+srv)?|mysql|postgres(ql)?|redis|mssql|oracle):\/\/[^\s]+/gi,
    severity: 'critical',
    category: 'database-credentials',
    description: 'Database connection string detected'
  },
  {
    name: 'JDBC Connection String',
    pattern: /jdbc:[\w]+:\/\/[^\s;]+/gi,
    severity: 'critical',
    category: 'database-credentials',
    description: 'JDBC connection string detected'
  },
  {
    name: 'SQL Server Password',
    pattern: /Password\s*=\s*[^;\s]+/gi,
    severity: 'critical',
    category: 'database-credentials',
    description: 'SQL Server password in connection string'
  },
  {
    name: 'PostgreSQL Password',
    pattern: /postgresql:\/\/[^:]+:[^@]+@/gi,
    severity: 'critical',
    category: 'database-credentials',
    description: 'PostgreSQL password in URL detected'
  },
  {
    name: 'MongoDB Credentials',
    pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/gi,
    severity: 'critical',
    category: 'database-credentials',
    description: 'MongoDB credentials in connection string'
  },

  // Private Keys
  {
    name: 'RSA Private Key',
    pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
    category: 'private-keys',
    description: 'Private key detected'
  },
  {
    name: 'SSH Private Key',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    severity: 'critical',
    category: 'private-keys',
    description: 'SSH private key detected'
  },
  {
    name: 'PEM Private Key',
    pattern: /-----BEGIN PRIVATE KEY-----/g,
    severity: 'critical',
    category: 'private-keys',
    description: 'PEM private key detected'
  },
  {
    name: 'PGP Private Key',
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    severity: 'critical',
    category: 'private-keys',
    description: 'PGP private key block detected'
  },

  // Authentication Tokens
  {
    name: 'Bearer Token',
    pattern: /[Bb]earer\s+[a-zA-Z0-9_\-\.=]+/g,
    severity: 'high',
    category: 'auth-tokens',
    description: 'Bearer token detected'
  },
  {
    name: 'JWT Token',
    pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    severity: 'high',
    category: 'auth-tokens',
    description: 'JSON Web Token (JWT) detected'
  },
  {
    name: 'Basic Auth',
    pattern: /Basic\s+[a-zA-Z0-9+=\/]+/gi,
    severity: 'critical',
    category: 'auth-tokens',
    description: 'Basic authentication credentials detected'
  },
  {
    name: 'OAuth Token',
    pattern: /[0-9a-f]{32}-[0-9a-f]{32}/gi,
    severity: 'high',
    category: 'auth-tokens',
    description: 'Potential OAuth token detected'
  },
  {
    name: 'GitHub Token',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    severity: 'critical',
    category: 'auth-tokens',
    description: 'GitHub personal access token detected'
  },
  {
    name: 'GitLab Token',
    pattern: /glpat-[a-zA-Z0-9_-]{20}/g,
    severity: 'critical',
    category: 'auth-tokens',
    description: 'GitLab personal access token detected'
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24})?/g,
    severity: 'critical',
    category: 'auth-tokens',
    description: 'Slack API token detected'
  },
  {
    name: 'Slack Webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,}\/[a-zA-Z0-9_]{24}/g,
    severity: 'high',
    category: 'auth-tokens',
    description: 'Slack webhook URL detected'
  },

  // Generic Secrets
  {
    name: 'Generic Secret',
    pattern: /(secret|password|passwd|pwd|pass)\s*[:=]\s*["\'][^"\']{8,}["\']/gi,
    severity: 'high',
    category: 'generic-secrets',
    description: 'Potential hardcoded secret detected'
  },
  {
    name: 'Generic API Key',
    pattern: /(api[_-]?key|apikey)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']/gi,
    severity: 'high',
    category: 'api-keys',
    description: 'Potential API key detected'
  },
  {
    name: 'Private Key File Reference',
    pattern: /["\'][^"\']*\.(pem|key|p12|pfx|pkcs12)["\']/gi,
    severity: 'medium',
    category: 'private-keys',
    description: 'Reference to private key file detected'
  },

  // Environment Variables
  {
    name: 'Sensitive Env Variable',
    pattern: /(SECRET|PASSWORD|TOKEN|KEY|PRIVATE)\s*=\s*[^\s]+/gi,
    severity: 'high',
    category: 'environment-variables',
    description: 'Sensitive environment variable with value'
  },

  // Certificates
  {
    name: 'Certificate',
    pattern: /-----BEGIN CERTIFICATE-----/g,
    severity: 'medium',
    category: 'certificates',
    description: 'Certificate detected'
  },

  // Kubernetes Secrets
  {
    name: 'Kubernetes Secret',
    pattern: /kind:\s*Secret\s*\n[\s\S]*?data:\s*\n[\s\S]*?:\s*[a-zA-Z0-9+/=]{20,}/gi,
    severity: 'high',
    category: 'kubernetes-secrets',
    description: 'Kubernetes Secret with encoded data detected'
  },

  // Terraform State
  {
    name: 'Terraform State Sensitive',
    pattern: /"password"\s*:\s*"[^"]+"/gi,
    severity: 'critical',
    category: 'terraform-state',
    description: 'Sensitive data in Terraform state'
  },

  // Twilio
  {
    name: 'Twilio API Key',
    pattern: /SK[0-9a-f]{32}/g,
    severity: 'critical',
    category: 'api-keys',
    description: 'Twilio API Key detected'
  },
  {
    name: 'Twilio Auth Token',
    pattern: /[0-9a-f]{32}/g,
    severity: 'high',
    category: 'auth-tokens',
    description: 'Potential Twilio Auth Token'
  },

  // Stripe
  {
    name: 'Stripe API Key',
    pattern: /sk_(live|test)_[0-9a-zA-Z]{24,}/g,
    severity: 'critical',
    category: 'api-keys',
    description: 'Stripe API key detected'
  },

  // SendGrid
  {
    name: 'SendGrid API Key',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: 'critical',
    category: 'api-keys',
    description: 'SendGrid API key detected'
  },

  // Heroku
  {
    name: 'Heroku API Key',
    pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
    severity: 'high',
    category: 'api-keys',
    description: 'Potential Heroku API key'
  }
];

export const EXCLUDED_PATHS = [
  'node_modules',
  'vendor',
  '.git',
  'dist',
  'build',
  'coverage',
  '*.min.js',
  '*.min.css',
  '*.map',
  'package-lock.json',
  'yarn.lock',
  'Gemfile.lock',
  'poetry.lock',
  'Cargo.lock',
  'go.sum',
  '.eslintcache',
  '.DS_Store',
  '*.log',
  '*.svg',
  '*.png',
  '*.jpg',
  '*.jpeg',
  '*.gif',
  '*.ico',
  '*.woff',
  '*.woff2',
  '*.ttf',
  '*.eot',
  '*.pdf',
  '*.zip',
  '*.tar',
  '*.gz',
  'test/**',
  'tests/**',
  '__tests__/**',
  'spec/**',
  '*.test.js',
  '*.spec.js',
  '*.test.ts',
  '*.spec.ts',
  '*.test.py',
  'test_*.py'
];
