import { IAIProvider } from './base-provider';
import { OpenAIProvider } from './providers/openai';
import { AzureOpenAIProvider } from './providers/azure';
import { AnthropicProvider } from './providers/anthropic';
import { GoogleAIProvider } from './providers/google';
import { OllamaProvider } from './providers/ollama';
import {
  AIProviderConfig,
  AIAnalysisRequest,
  AIAnalysisResult,
  AISettings,
  AIUsageStats,
  AIProviderType
} from '../types/ai';
import * as fs from 'fs';
import * as path from 'path';

export class AIManager {
  private providers: Map<string, IAIProvider> = new Map();
  private settings: AISettings;
  private cache: Map<string, { result: AIAnalysisResult; timestamp: number }> = new Map();
  private readonly CACHE_TTL = 1000 * 60 * 60; // 1 hour

  constructor(settings?: AISettings) {
    this.settings = settings || this.getDefaultSettings();
    this.initializeProviders();
  }

  private getDefaultSettings(): AISettings {
    return {
      enabled: false,
      providers: [],
      prompts: [],
      fallbackToStaticRules: true,
      batchSize: 5,
      maxConcurrency: 3,
      enableCostTracking: true,
      enableUsageLogging: true,
      cacheResults: true,
      cacheTtl: this.CACHE_TTL
    };
  }

  private initializeProviders(): void {
    for (const config of this.settings.providers) {
      if (!config.enabled) continue;

      try {
        const provider = this.createProvider(config);
        if (provider) {
          this.providers.set(config.name, provider);
        }
      } catch (error) {
        console.warn(`Failed to initialize provider ${config.name}:`, error);
      }
    }
  }

  private createProvider(config: AIProviderConfig): IAIProvider | null {
    switch (config.type) {
      case 'openai':
        return new OpenAIProvider(config);
      case 'azure-openai':
        return new AzureOpenAIProvider(config);
      case 'anthropic':
        return new AnthropicProvider(config);
      case 'google-ai':
        return new GoogleAIProvider(config);
      case 'ollama':
        return new OllamaProvider(config);
      default:
        return null;
    }
  }

  async analyze(request: AIAnalysisRequest): Promise<AIAnalysisResult | null> {
    if (!this.settings.enabled || this.providers.size === 0) {
      return null;
    }

    // Check cache
    if (this.settings.cacheResults) {
      const cacheKey = this.getCacheKey(request);
      const cached = this.cache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.settings.cacheTtl) {
        return cached.result;
      }
    }

    // Get the best available provider
    const provider = this.getBestProvider();
    if (!provider) {
      throw new Error('No available AI providers configured');
    }

    try {
      const result = await provider.analyze(request);

      // Cache the result
      if (this.settings.cacheResults) {
        const cacheKey = this.getCacheKey(request);
        this.cache.set(cacheKey, { result, timestamp: Date.now() });
      }

      return result;
    } catch (error) {
      console.error(`AI analysis failed with provider ${provider.name}:`, error);
      
      // Try fallback providers
      const fallbackProvider = this.getFallbackProvider(provider.name);
      if (fallbackProvider) {
        try {
          return await fallbackProvider.analyze(request);
        } catch (fallbackError) {
          console.error(`Fallback AI analysis also failed:`, fallbackError);
        }
      }

      if (this.settings.fallbackToStaticRules) {
        return null;
      }

      throw error;
    }
  }

  async analyzeBatch(requests: AIAnalysisRequest[]): Promise<(AIAnalysisResult | null)[]> {
    if (!this.settings.enabled || this.providers.size === 0) {
      return requests.map(() => null);
    }

    const results: (AIAnalysisResult | null)[] = [];
    const batchSize = this.settings.batchSize;
    const concurrency = this.settings.maxConcurrency;

    // Process in batches with concurrency control
    for (let i = 0; i < requests.length; i += batchSize) {
      const batch = requests.slice(i, i + batchSize);
      const batchPromises = batch.map(request => this.analyze(request));

      const batchResults = await Promise.allSettled(batchPromises);
      
      for (const result of batchResults) {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        } else {
          console.error('Batch analysis failed:', result.reason);
          results.push(null);
        }
      }
    }

    return results;
  }

  private getBestProvider(): IAIProvider | null {
    const enabledProviders = Array.from(this.providers.values()).filter(p => p.isEnabled);

    if (enabledProviders.length === 0) {
      return null;
    }

    // Simple selection strategy - can be enhanced with cost, latency, etc.
    return enabledProviders[0];
  }

  private getFallbackProvider(excludeName: string): IAIProvider | null {
    const providers = Array.from(this.providers.values())
      .filter(p => p.isEnabled && p.name !== excludeName);

    return providers.length > 0 ? providers[0] : null;
  }

  private getCacheKey(request: AIAnalysisRequest): string {
    const content = `${request.filePath}-${request.fileType}-${request.codeSnippet.substring(0, 100)}`;
    return Buffer.from(content).toString('base64');
  }

  // Configuration management
  updateSettings(settings: AISettings): void {
    this.settings = { ...settings };
    
    // Reinitialize providers with new settings
    this.providers.clear();
    this.initializeProviders();
  }

  getSettings(): AISettings {
    return { ...this.settings };
  }

  getProvider(name: string): IAIProvider | undefined {
    return this.providers.get(name);
  }

  getAllProviders(): IAIProvider[] {
    return Array.from(this.providers.values());
  }

  getEnabledProviders(): IAIProvider[] {
    return Array.from(this.providers.values()).filter(p => p.isEnabled);
  }

  addProvider(config: AIProviderConfig): void {
    const provider = this.createProvider(config);
    if (provider) {
      this.providers.set(config.name, provider);
      this.settings.providers.push(config);
    }
  }

  removeProvider(name: string): boolean {
    const removed = this.providers.delete(name);
    if (removed) {
      this.settings.providers = this.settings.providers.filter(p => p.name !== name);
    }
    return removed;
  }

  async validateProvider(name: string): Promise<boolean> {
    const provider = this.providers.get(name);
    if (!provider) {
      return false;
    }

    try {
      return await provider.validateConfig();
    } catch {
      return false;
    }
  }

  // Usage statistics and monitoring
  getGlobalUsageStats(): Record<string, AIUsageStats> {
    const stats: Record<string, AIUsageStats> = {};
    
    for (const [name, provider] of this.providers) {
      stats[name] = provider.getUsageStats();
    }

    return stats;
  }

  resetAllStats(): void {
    for (const provider of this.providers.values()) {
      provider.resetStats();
    }
  }

  // Cost management
  getTotalCost(): number {
    let total = 0;
    for (const provider of this.providers.values()) {
      total += provider.getUsageStats().totalCost;
    }
    return total;
  }

  getProviderCosts(): Record<string, number> {
    const costs: Record<string, number> = {};
    
    for (const [name, provider] of this.providers) {
      costs[name] = provider.getUsageStats().totalCost;
    }

    return costs;
  }

  // Cache management
  clearCache(): void {
    this.cache.clear();
  }

  getCacheStats(): { size: number; hits: number; misses: number } {
    return {
      size: this.cache.size,
      hits: 0, // Could implement hit/miss tracking
      misses: 0
    };
  }

  // Configuration persistence
  saveSettings(filePath: string): void {
    const settingsToSave = {
      ...this.settings,
      providers: this.settings.providers.map(p => ({
        ...p,
        apiKey: p.apiKey ? '[REDACTED]' : undefined // Don't save sensitive data
      }))
    };

    fs.writeFileSync(filePath, JSON.stringify(settingsToSave, null, 2));
  }

  static loadSettings(filePath: string): AISettings | null {
    try {
      if (fs.existsSync(filePath)) {
        const data = fs.readFileSync(filePath, 'utf-8');
        return JSON.parse(data);
      }
    } catch (error) {
      console.error('Failed to load AI settings:', error);
    }
    return null;
  }

  // Cleanup
  async shutdown(): Promise<void> {
    for (const provider of this.providers.values()) {
      await provider.shutdown();
    }
    this.clearCache();
  }
}

// Factory function for easy initialization
export async function createAIManager(configPath?: string): Promise<AIManager> {
  let settings: AISettings | undefined;
  
  if (configPath) {
    settings = AIManager.loadSettings(configPath);
  }

  const manager = new AIManager(settings);
  
  // Initialize providers
  for (const provider of manager.getAllProviders()) {
    try {
      await provider.initialize();
    } catch (error) {
      console.warn(`Failed to initialize provider ${provider.name}:`, error);
    }
  }

  return manager;
}