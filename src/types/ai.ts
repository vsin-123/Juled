import { SeverityLevel, SecurityCategory, OwaspCategory } from './index';

export type AIProviderType = 'openai' | 'azure-openai' | 'anthropic' | 'google-ai' | 'ollama';

export interface AIProviderConfig {
  type: AIProviderType;
  name: string;
  enabled: boolean;
  apiKey?: string;
  apiEndpoint?: string;
  model?: string;
  maxTokens?: number;
  temperature?: number;
  organizationId?: string;
  projectId?: string;
  deploymentName?: string;
  apiVersion?: string;
  customHeaders?: Record<string, string>;
  rateLimit?: {
    requestsPerMinute: number;
    requestsPerHour: number;
  };
  costTracking?: {
    enabled: boolean;
    budgetLimit?: number;
  };
}

export interface AIAnalysisRequest {
  codeSnippet: string;
  filePath: string;
  fileType: string;
  language?: string;
  context?: string;
  scanOptions?: {
    enableOwasp: boolean;
    enableSecrets: boolean;
    enableInfrastructure: boolean;
  };
}

export interface AIAnalysisResult {
  id: string;
  findings: AIFinding[];
  summary: string;
  confidence: number;
  processingTime: number;
  tokensUsed?: number;
  cost?: number;
}

export interface AIFinding {
  severity: SeverityLevel;
  category: SecurityCategory;
  owaspCategory?: OwaspCategory;
  title: string;
  description: string;
  lineStart?: number;
  lineEnd?: number;
  remediation: string;
  references: string[];
  cwe?: string;
  confidence: number;
  falsePositive?: boolean;
  customMetadata?: Record<string, unknown>;
}

export interface AIPromptTemplate {
  id: string;
  name: string;
  description: string;
  template: string;
  variables: string[];
  providerType: AIProviderType;
  model?: string;
  maxTokens?: number;
}

export interface AIUsageStats {
  providerType: AIProviderType;
  totalRequests: number;
  totalTokens: number;
  totalCost: number;
  averageResponseTime: number;
  lastUsed?: Date;
  errors: number;
}

export interface SecurityAnalysisContext {
  repository: {
    name: string;
    owner: string;
    language?: string;
    framework?: string;
  };
  pullRequest: {
    number: number;
    title: string;
    description?: string;
    author: string;
  };
  fileMetadata: {
    path: string;
    type: string;
    size: number;
    language?: string;
  };
  existingFindings?: {
    ruleId: string;
    severity: SeverityLevel;
    message: string;
  }[];
}

export interface AISettings {
  enabled: boolean;
  defaultProvider?: AIProviderType;
  providers: AIProviderConfig[];
  prompts: AIPromptTemplate[];
  fallbackToStaticRules: boolean;
  batchSize: number;
  maxConcurrency: number;
  enableCostTracking: boolean;
  enableUsageLogging: boolean;
  cacheResults: boolean;
  cacheTtl: number; // in seconds
}