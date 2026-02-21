export interface SecurityFinding {
  id: string;
  ruleId: string;
  severity: SeverityLevel;
  category: SecurityCategory;
  filePath: string;
  lineNumber: number;
  columnNumber?: number;
  message: string;
  description: string;
  remediation?: string;
  references?: string[];
  codeSnippet?: string;
  owaspCategory?: OwaspCategory;
  confidence: ConfidenceLevel;
  metadata?: Record<string, unknown>;
  // AI-enhanced fields
  aiEnhanced?: boolean;
  aiProvider?: string;
  aiConfidence?: number;
  aiModel?: string;
  aiProcessingTime?: number;
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ConfidenceLevel = 'high' | 'medium' | 'low';

export type SecurityCategory =
  | 'sql-injection'
  | 'command-injection'
  | 'xss'
  | 'path-traversal'
  | 'hardcoded-secrets'
  | 'insecure-configuration'
  | 'weak-cryptography'
  | 'authentication'
  | 'authorization'
  | 'input-validation'
  | 'dependency-vulnerability'
  | 'infrastructure'
  | 'container-security'
  | 'secrets-management'
  | 'access-control'
  | 'logging'
  | 'error-handling'
  | 'file-permissions'
  | 'network-security'
  | 'data-validation';

export type OwaspCategory =
  | 'A01:2021-Broken Access Control'
  | 'A02:2021-Cryptographic Failures'
  | 'A03:2021-Injection'
  | 'A04:2021-Insecure Design'
  | 'A05:2021-Security Misconfiguration'
  | 'A06:2021-Vulnerable and Outdated Components'
  | 'A07:2021-Identification and Authentication Failures'
  | 'A08:2021-Software and Data Integrity Failures'
  | 'A09:2021-Security Logging and Monitoring Failures'
  | 'A10:2021-Server-Side Request Forgery (SSRF)';

export interface FileType {
  name: string;
  extensions: string[];
  filenames?: string[];
  mimeTypes?: string[];
  category: FileCategory;
  scanner: string;
}

export type FileCategory =
  | 'database'
  | 'configuration'
  | 'markup'
  | 'data'
  | 'container'
  | 'infrastructure'
  | 'build'
  | 'source-code'
  | 'documentation';

export interface ScannerConfig {
  name: string;
  enabled: boolean;
  fileTypes: string[];
  options?: Record<string, unknown>;
}

export interface ScanResult {
  filePath: string;
  fileType: string;
  findings: SecurityFinding[];
  scanDuration: number;
  scannedAt: Date;
  scannerVersion: string;
}

export interface ScanOptions {
  directory: string;
  includeExtensions?: string[];
  excludeExtensions?: string[];
  excludePaths?: string[];
  failOn?: SeverityLevel;
  enableOwasp?: boolean;
  enableSecrets?: boolean;
  customRulesPath?: string;
  outputFormat?: 'json' | 'sarif' | 'markdown';
  verbose?: boolean;
  parallel?: boolean;
  maxWorkers?: number;
  // AI-related options
  enableAiAnalysis?: boolean;
  aiProvider?: string;
  aiConfigPath?: string;
  aiBatchSize?: number;
  aiMaxConcurrency?: number;
  aiCostLimit?: number;
  aiCacheResults?: boolean;
}

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  severity: SeverityLevel;
  category: SecurityCategory;
  owaspCategory?: OwaspCategory;
  fileTypes: string[];
  patterns: RegExp[];
  negativePatterns?: RegExp[];
  excludedPaths?: string[];
  message: string;
  remediation?: string;
  references?: string[];
  metadata?: Record<string, unknown>;
}

export interface FileDetectionResult {
  filePath: string;
  detectedType: string;
  confidence: number;
  extension: string;
  mimeType?: string;
  contentSample?: string;
}

export interface GitHubPRContext {
  owner: string;
  repo: string;
  pullNumber: number;
  sha: string;
  baseSha: string;
  headSha: string;
  files: PRFile[];
}

export interface PRFile {
  filename: string;
  status: 'added' | 'modified' | 'removed' | 'renamed';
  additions: number;
  deletions: number;
  patch?: string;
  previousFilename?: string;
}

export interface ReportData {
  scanId: string;
  scannedAt: Date;
  totalFiles: number;
  totalFindings: number;
  findingsBySeverity: Record<SeverityLevel, number>;
  findingsByCategory: Record<SecurityCategory, number>;
  findingsByOwasp: Record<OwaspCategory, number>;
  results: ScanResult[];
  summary: string;
}

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: SeverityLevel;
  category: string;
  description: string;
}

export interface SQLInjectionPattern {
  pattern: RegExp;
  dialect: string[];
  context: string[];
  severity: SeverityLevel;
}

export interface AIAnalysisMetadata {
  provider: string;
  model: string;
  tokensUsed: number;
  cost: number;
  processingTime: number;
  timestamp: Date;
}

export interface EnhancedScanResult extends ScanResult {
  aiAnalysis?: AIAnalysisMetadata;
  aiFindings?: SecurityFinding[];
}
