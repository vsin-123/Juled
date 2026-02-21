import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { AIManager } from '../ai/manager';
import { AppConfig, defaultConfig, createAIProviderConfig, validateAIProviderConfig } from '../config/app';
import { encryptAPIKey, decryptAPIKey, getEncryptionService } from '../utils/encryption';
import * as fs from 'fs';
import * as path from 'path';

const app = express();
const config: AppConfig = { ...defaultConfig };
let aiManager: AIManager | null = null;

// Middleware
app.use(cors());
app.use(express.json());

// Request logging
app.use((req: Request, _res: Response, next: NextFunction) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Health check
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// AI Configuration Routes

// Get all AI settings
app.get('/api/ai/settings', (_req: Request, res: Response) => {
  const settings = aiManager?.getSettings() || config.ai;
  
  // Mask sensitive data
  const safeSettings = {
    ...settings,
    providers: settings.providers.map(p => ({
      ...p,
      apiKey: p.apiKey ? '********' : undefined
    }))
  };
  
  res.json(safeSettings);
});

// Update AI settings
app.put('/api/ai/settings', (req: Request, res: Response) => {
  try {
    const { settings } = req.body;
    
    if (!settings) {
      return res.status(400).json({ error: 'Settings object is required' });
    }
    
    // Encrypt any new API keys
    if (settings.providers) {
      settings.providers = settings.providers.map((p: any) => {
        if (p.apiKey && !p.apiKey.startsWith('********')) {
          p.apiKey = encryptAPIKey(p.apiKey);
        }
        return p;
      });
    }
    
    if (aiManager) {
      aiManager.updateSettings(settings);
    } else {
      config.ai = settings;
    }
    
    res.json({ success: true, message: 'AI settings updated successfully' });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to update AI settings', details: message });
  }
});

// Get specific provider
app.get('/api/ai/providers/:name', (req: Request, res: Response) => {
  const { name } = req.params;
  const provider = aiManager?.getProvider(name);
  
  if (!provider) {
    return res.status(404).json({ error: 'Provider not found' });
  }
  
  const stats = provider.getUsageStats();
  res.json({
    name: provider.name,
    type: provider.type,
    enabled: provider.isEnabled,
    stats
  });
});

// Add a new provider
app.post('/api/ai/providers', async (req: Request, res: Response) => {
  try {
    const providerConfig = req.body;
    
    // Validate
    const errors = validateAIProviderConfig(providerConfig);
    if (errors.length > 0) {
      return res.status(400).json({ errors });
    }
    
    // Encrypt API key
    if (providerConfig.apiKey) {
      providerConfig.apiKey = encryptAPIKey(providerConfig.apiKey);
    }
    
    if (aiManager) {
      aiManager.addProvider(providerConfig);
      await aiManager.validateProvider(providerConfig.name);
    } else {
      config.ai.providers.push(providerConfig);
    }
    
    res.status(201).json({ success: true, message: `Provider ${providerConfig.name} added successfully` });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to add provider', details: message });
  }
});

// Remove a provider
app.delete('/api/ai/providers/:name', (req: Request, res: Response) => {
  const { name } = req.params;
  
  if (aiManager) {
    const removed = aiManager.removeProvider(name);
    if (removed) {
      return res.json({ success: true, message: `Provider ${name} removed` });
    }
  }
  
  res.status(404).json({ error: 'Provider not found' });
});

// Validate provider configuration
app.post('/api/ai/providers/validate', async (req: Request, res: Response) => {
  try {
    const providerConfig = req.body;
    
    // Temporarily add provider for validation
    if (aiManager) {
      aiManager.addProvider(providerConfig);
      const isValid = await aiManager.validateProvider(providerConfig.name);
      aiManager.removeProvider(providerConfig.name);
      
      res.json({ valid: isValid });
    } else {
      res.status(400).json({ error: 'AI manager not initialized' });
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.json({ valid: false, error: message });
  }
});

// Usage statistics
app.get('/api/ai/usage', (_req: Request, res: Response) => {
  if (!aiManager) {
    return res.json({ providers: {}, totalCost: 0 });
  }
  
  const stats = aiManager.getGlobalUsageStats();
  const totalCost = aiManager.getTotalCost();
  
  res.json({
    providers: stats,
    totalCost,
    timestamp: new Date().toISOString()
  });
});

// Cost tracking
app.get('/api/ai/costs', (_req: Request, res: Response) => {
  if (!aiManager) {
    return res.json({ costs: {}, total: 0 });
  }
  
  const costs = aiManager.getProviderCosts();
  const total = aiManager.getTotalCost();
  
  res.json({
    costs,
    total,
    currency: 'USD'
  });
});

// Clear AI cache
app.delete('/api/ai/cache', (_req: Request, res: Response) => {
  if (aiManager) {
    aiManager.clearCache();
  }
  res.json({ success: true, message: 'Cache cleared' });
});

// Configuration file management
app.get('/api/config', (_req: Request, res: Response) => {
  res.json({
    app: config.app,
    logging: config.logging,
    database: config.database,
    ai: {
      ...config.ai,
      providers: config.ai.providers.map(p => ({
        ...p,
        apiKey: p.apiKey ? '********' : undefined
      }))
    }
  });
});

app.put('/api/config', (req: Request, res: Response) => {
  try {
    const newConfig = req.body;
    
    // Validate and merge config
    if (newConfig.app) config.app = { ...config.app, ...newConfig.app };
    if (newConfig.logging) config.logging = { ...config.logging, ...newConfig.logging };
    if (newConfig.database) config.database = { ...config.database, ...newConfig.database };
    
    res.json({ success: true, message: 'Configuration updated' });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to update configuration', details: message });
  }
});

app.post('/api/config/save', (req: Request, res: Response) => {
  try {
    const { path: configPath } = req.body;
    
    if (!configPath) {
      return res.status(400).json({ error: 'Configuration path is required' });
    }
    
    // Save config without sensitive data
    const configToSave = {
      ...config,
      ai: {
        ...config.ai,
        providers: config.ai.providers.map(p => ({
          ...p,
          apiKey: undefined
        }))
      },
      security: {
        ...config.security,
        encryptionKey: undefined,
        sessionSecret: undefined
      },
      github: {
        ...config.github,
        privateKey: undefined,
        webhookSecret: undefined
      }
    };
    
    const dir = path.dirname(configPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(configPath, JSON.stringify(configToSave, null, 2));
    
    res.json({ success: true, message: `Configuration saved to ${configPath}` });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to save configuration', details: message });
  }
});

// Error handling
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error', message: err.message });
});

// Initialize and start server
export function startServer(port?: number): void {
  const serverPort = port || config.app.port;
  
  app.listen(serverPort, () => {
    console.log(`PR Security Scanner API server running on port ${serverPort}`);
    console.log(`Health check: http://localhost:${serverPort}/health`);
    console.log(`API docs: http://localhost:${serverPort}/api`);
  });
}

export function initializeAIManager(settings?: any): void {
  aiManager = new AIManager(settings || config.ai);
}

export { app, config, aiManager };
