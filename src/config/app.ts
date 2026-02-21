import { AISettings, AIProviderConfig, AIProviderType } from '../types/ai';

export interface AppConfig {
  app: {
    name: string;
    version: string;
    environment: 'development' | 'production';
    port: number;
  };
  logging: {
    level: 'debug' | 'info' | 'warn' | 'error';
    format: 'json' | 'text';
    destination: string;
  };
  database: {
    type: 'sqlite' | 'postgres' | 'mysql';
    path?: string;
    host?: string;
    port?: number;
    name?: string;
    user?: string;
    password?: string;
  };
  security: {
    encryptionKey: string;
    sessionSecret: string;
    rateLimit: {
      windowMs: number;
      maxRequests: number;
    };
  };
  github: {
    appId: string;
    privateKey: string;
    webhookSecret: string;
    permissions: {
      contents: 'read' | 'write';
      pullRequests: 'read' | 'write';
      issues: 'read' | 'write';
      checks: 'read' | 'write';
      metadata: 'read';
    };
  };
  ai: AISettings;
}

export const defaultConfig: AppConfig = {
  app: {
    name: 'PR Security Scanner',
    version: '1.0.0',
    environment: 'development',
    port: 3000
  },
  logging: {
    level: 'info',
    format: 'json',
    destination: 'logs/app.log'
  },
  database: {
    type: 'sqlite',
    path: 'data/scanner.db'
  },
  security: {
    encryptionKey: process.env.ENCRYPTION_KEY || '',
    sessionSecret: process.env.SESSION_SECRET || '',
    rateLimit: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 100
    }
  },
  github: {
    appId: process.env.GITHUB_APP_ID || '',
    privateKey: process.env.GITHUB_PRIVATE_KEY || '',
    webhookSecret: process.env.GITHUB_WEBHOOK_SECRET || '',
    permissions: {
      contents: 'read',
      pullRequests: 'write',
      issues: 'read',
      checks: 'write',
      metadata: 'read'
    }
  },
  ai: {
    enabled: false,
    defaultProvider: undefined,
    providers: [],
    prompts: [],
    fallbackToStaticRules: true,
    batchSize: 5,
    maxConcurrency: 3,
    enableCostTracking: true,
    enableUsageLogging: true,
    cacheResults: true,
    cacheTtl: 3600
  }
};

export function createAIProviderConfig(
  type: AIProviderType,
  name: string,
  apiKey: string,
  options?: Partial<AIProviderConfig>
): AIProviderConfig {
  const baseConfig: AIProviderConfig = {
    type,
    name,
    enabled: true,
    apiKey,
    model: getDefaultModel(type),
    maxTokens: 4000,
    temperature: 0.1
  };

  return { ...baseConfig, ...options };
}

function getDefaultModel(type: AIProviderType): string {
  const defaults: Record<AIProviderType, string> = {
    'openai': 'gpt-4-turbo-preview',
    'azure-openai': 'gpt-4',
    'anthropic': 'claude-3-opus-20240229',
    'google-ai': 'gemini-pro',
    'ollama': 'llama2'
  };
  return defaults[type];
}

export function validateAIProviderConfig(config: AIProviderConfig): string[] {
  const errors: string[] = [];

  if (!config.name) {
    errors.push('Provider name is required');
  }

  if (!config.apiKey && config.type !== 'ollama') {
    errors.push('API key is required');
  }

  if (config.type === 'azure-openai') {
    if (!config.apiEndpoint) {
      errors.push('Azure endpoint is required');
    }
    if (!config.deploymentName) {
      errors.push('Azure deployment name is required');
    }
  }

  return errors;
}
