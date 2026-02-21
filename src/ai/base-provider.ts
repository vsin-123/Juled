import { AIProviderConfig, AIAnalysisRequest, AIAnalysisResult, AIUsageStats } from '../types/ai';

export interface IAIProvider {
  readonly config: AIProviderConfig;
  readonly name: string;
  readonly type: string;
  readonly isEnabled: boolean;
  
  initialize(): Promise<void>;
  analyze(request: AIAnalysisRequest): Promise<AIAnalysisResult>;
  validateConfig(): Promise<boolean>;
  getUsageStats(): AIUsageStats;
  resetStats(): void;
  shutdown(): Promise<void>;
  
  // Utility methods
  estimateTokens(text: string): number;
  calculateCost(tokens: number): number;
}

export abstract class BaseAIProvider implements IAIProvider {
  protected _config: AIProviderConfig;
  protected _usageStats: AIUsageStats;
  protected _isInitialized: boolean = false;

  constructor(config: AIProviderConfig) {
    this._config = { ...config };
    this._usageStats = {
      providerType: config.type,
      totalRequests: 0,
      totalTokens: 0,
      totalCost: 0,
      averageResponseTime: 0,
      errors: 0
    };
  }

  abstract initialize(): Promise<void>;
  abstract analyze(request: AIAnalysisRequest): Promise<AIAnalysisResult>;
  abstract validateConfig(): Promise<boolean>;
  abstract shutdown(): Promise<void>;

  get config(): AIProviderConfig {
    return this._config;
  }

  get name(): string {
    return this._config.name;
  }

  get type(): string {
    return this._config.type;
  }

  get isEnabled(): boolean {
    return this._config.enabled;
  }

  getUsageStats(): AIUsageStats {
    return { ...this._usageStats };
  }

  resetStats(): void {
    this._usageStats = {
      providerType: this._config.type,
      totalRequests: 0,
      totalTokens: 0,
      totalCost: 0,
      averageResponseTime: 0,
      errors: 0
    };
  }

  protected updateStats(responseTime: number, tokens?: number, cost?: number): void {
    this._usageStats.totalRequests++;
    
    if (tokens) {
      this._usageStats.totalTokens += tokens;
    }
    
    if (cost) {
      this._usageStats.totalCost += cost;
    }
    
    // Update average response time
    const currentAvg = this._usageStats.averageResponseTime;
    const count = this._usageStats.totalRequests;
    this._usageStats.averageResponseTime = (currentAvg * (count - 1) + responseTime) / count;
    
    this._usageStats.lastUsed = new Date();
  }

  protected recordError(): void {
    this._usageStats.errors++;
  }

  abstract estimateTokens(text: string): number;
  abstract calculateCost(tokens: number): number;
}