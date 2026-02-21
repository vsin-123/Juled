import { BaseAIProvider } from './base-provider';
import { AIProviderConfig, AIAnalysisRequest, AIAnalysisResult, AIUsageStats } from '../types/ai';
import { v4 as uuidv4 } from 'uuid';

const SECURITY_ANALYSIS_PROMPT = `You are a security expert analyzing code for vulnerabilities. Analyze the following code snippet and identify security issues.

File: {{filePath}}
File Type: {{fileType}}
Language: {{language}}

Code:
\`\`\`
{{codeSnippet}}
\`\`\`

{{#if context}}
Context:
{{context}}
{{/if}}

Provide your analysis in JSON format with the following structure:
{
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "category": "sql-injection|xss|hardcoded-secrets|...",
      "owaspCategory": "A01:2021-...|A02:2021-...",
      "title": "Brief title of the finding",
      "description": "Detailed description of the vulnerability",
      "lineStart": number,
      "lineEnd": number,
      "remediation": "How to fix this issue",
      "references": ["CWE-XXX", "URL to docs"],
      "cwe": "CWE-XXX",
      "confidence": 0.0-1.0
    }
  ],
  "summary": "Brief overall summary of the analysis"
}

Only include findings that are actual security issues. Do not include false positives or informational findings unless they are critical.`;

export class OpenAIProvider extends BaseAIProvider {
  private openai: any;

  constructor(config: AIProviderConfig) {
    super(config);
    this._config.model = config.model || 'gpt-4-turbo-preview';
    this._config.maxTokens = config.maxTokens || 4000;
    this._config.temperature = config.temperature ?? 0.1;
  }

  async initialize(): Promise<void> {
    if (!this._config.apiKey) {
      throw new Error('OpenAI API key is required');
    }

    try {
      const { OpenAI } = await import('openai');
      this.openai = new OpenAI({
        apiKey: this._config.apiKey,
        organization: this._config.organizationId,
        maxRetries: 3
      });
      this._isInitialized = true;
    } catch (error) {
      throw new Error(`Failed to initialize OpenAI: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async analyze(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    const startTime = Date.now();
    
    if (!this._isInitialized) {
      await this.initialize();
    }

    try {
      const prompt = this.buildPrompt(request);
      
      const response = await this.openai.chat.completions.create({
        model: this._config.model!,
        messages: [
          {
            role: 'system',
            content: 'You are a security expert specializing in application security, OWASP Top 10, and secure coding practices. Provide detailed, accurate security analysis.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: this._config.temperature,
        max_tokens: this._config.maxTokens,
        response_format: { type: 'json_object' }
      });

      const content = response.choices[0]?.message?.content || '{}';
      const tokensUsed = response.usage?.total_tokens || this.estimateTokens(content);
      const responseTime = Date.now() - startTime;

      const analysis = this.parseResponse(content);
      
      this.updateStats(responseTime, tokensUsed, this.calculateCost(tokensUsed));

      return {
        id: uuidv4(),
        findings: analysis.findings,
        summary: analysis.summary,
        confidence: this.calculateConfidence(analysis.findings),
        processingTime: responseTime,
        tokensUsed,
        cost: this.calculateCost(tokensUsed)
      };
    } catch (error) {
      this.recordError();
      throw new Error(`OpenAI analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async validateConfig(): Promise<boolean> {
    if (!this._config.apiKey) {
      return false;
    }

    try {
      await this.initialize();
      // Make a minimal test request
      await this.openai.chat.completions.create({
        model: this._config.model!,
        messages: [{ role: 'user', content: 'test' }],
        max_tokens: 5
      });
      return true;
    } catch {
      return false;
    }
  }

  async shutdown(): Promise<void> {
    this._isInitialized = false;
  }

  estimateTokens(text: string): number {
    // Rough estimation: 1 token ≈ 4 characters for English text
    return Math.ceil(text.length / 4);
  }

  calculateCost(tokens: number): number {
    const pricing: Record<string, { input: number; output: number }> = {
      'gpt-4-turbo-preview': { input: 0.01, output: 0.03 },
      'gpt-4': { input: 0.03, output: 0.06 },
      'gpt-4-32k': { input: 0.06, output: 0.12 },
      'gpt-3.5-turbo': { input: 0.0015, output: 0.002 }
    };

    const modelPricing = pricing[this._config.model || 'gpt-4-turbo-preview'] || { input: 0.01, output: 0.03 };
    return (tokens * modelPricing.input) / 1000;
  }

  private buildPrompt(request: AIAnalysisRequest): string {
    let prompt = SECURITY_ANALYSIS_PROMPT
      .replace(/\{\{filePath\}\}/g, request.filePath)
      .replace(/\{\{fileType\}\}/g, request.fileType)
      .replace(/\{\{language\}\}/g, request.language || 'unknown')
      .replace(/\{\{codeSnippet\}\}/g, request.codeSnippet)
      .replace(/\{\{context\}\}/g, request.context || '');

    if (request.scanOptions) {
      const options = request.scanOptions;
      prompt += `\n\nScan options:
- OWASP Top 10: ${options.enableOwasp ? 'enabled' : 'disabled'}
- Secrets detection: ${options.enableSecrets ? 'enabled' : 'disabled'}
- Infrastructure security: ${options.enableInfrastructure ? 'enabled' : 'disabled'}`;
    }

    return prompt;
  }

  private parseResponse(content: string): { findings: any[]; summary: string } {
    try {
      const parsed = JSON.parse(content);
      return {
        findings: Array.isArray(parsed.findings) ? parsed.findings : [],
        summary: parsed.summary || 'Analysis complete'
      };
    } catch {
      return {
        findings: [],
        summary: 'Failed to parse AI response'
      };
    }
  }

  private calculateConfidence(findings: any[]): number {
    if (findings.length === 0) return 0;
    
    const totalConfidence = findings.reduce((sum, f) => sum + (f.confidence || 0.5), 0);
    return totalConfidence / findings.length;
  }
}
