import { BaseAIProvider } from '../base-provider';
import { AIProviderConfig, AIAnalysisRequest, AIAnalysisResult } from '../../types/ai';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';

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

Only include findings that are actual security issues.`;

export class AnthropicProvider extends BaseAIProvider {
  private baseUrl = 'https://api.anthropic.com';

  constructor(config: AIProviderConfig) {
    super(config);
    this._config.model = config.model || 'claude-3-opus-20240229';
    this._config.maxTokens = config.maxTokens || 4096;
  }

  async initialize(): Promise<void> {
    if (!this._config.apiKey) {
      throw new Error('Anthropic API key is required');
    }

    this._isInitialized = true;
  }

  async analyze(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    const startTime = Date.now();

    if (!this._isInitialized) {
      await this.initialize();
    }

    try {
      const prompt = this.buildPrompt(request);
      const humanMessage = `Analyze the following code for security vulnerabilities:\n\n${prompt}`;

      const response = await axios.post(
        `${this.baseUrl}/v1/messages`,
        {
          model: this._config.model,
          max_tokens: this._config.maxTokens,
          messages: [
            {
              role: 'user',
              content: humanMessage
            }
          ],
          system: 'You are a security expert specializing in application security, OWASP Top 10, and secure coding practices. Provide detailed, accurate security analysis in JSON format.',
          temperature: this._config.temperature ?? 0.1
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': this._config.apiKey,
            'anthropic-version': '2023-06-01'
          }
        }
      );

      const content = response.data.content[0]?.text || '{}';
      const tokensUsed = (response.data.usage?.input_tokens || 0) + (response.data.usage?.output_tokens || 0);
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
      const message = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Anthropic analysis failed: ${message}`);
    }
  }

  async validateConfig(): Promise<boolean> {
    if (!this._config.apiKey) {
      return false;
    }

    try {
      await this.initialize();
      return true;
    } catch {
      return false;
    }
  }

  async shutdown(): Promise<void> {
    this._isInitialized = false;
  }

  estimateTokens(text: string): number {
    // Anthropic estimates ~3 tokens per word
    const words = text.split(/\s+/).length;
    return Math.ceil(words * 1.3);
  }

  calculateCost(tokens: number): number {
    const pricing: Record<string, { input: number; output: number }> = {
      'claude-3-opus-20240229': { input: 0.015, output: 0.075 },
      'claude-3-sonnet-20240229': { input: 0.003, output: 0.015 },
      'claude-3-haiku-20240307': { input: 0.00025, output: 0.00125 }
    };

    const modelPricing = pricing[this._config.model || 'claude-3-opus-20240229'];
    const inputCost = (tokens / 2) * (modelPricing.input / 1000);
    const outputCost = (tokens / 2) * (modelPricing.output / 1000);
    
    return inputCost + outputCost;
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
