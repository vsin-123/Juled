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

export class OllamaProvider extends BaseAIProvider {
  private baseUrl: string;

  constructor(config: AIProviderConfig) {
    super(config);
    this._config.model = config.model || 'llama2';
    this.baseUrl = config.apiEndpoint || 'http://localhost:11434';
  }

  async initialize(): Promise<void> {
    if (!this._config.apiEndpoint) {
      this.baseUrl = 'http://localhost:11434';
    }

    // Test connection
    try {
      await axios.get(`${this.baseUrl}/api/tags`);
      this._isInitialized = true;
    } catch (error) {
      throw new Error(`Cannot connect to Ollama at ${this.baseUrl}. Make sure Ollama is running.`);
    }
  }

  async analyze(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    const startTime = Date.now();

    if (!this._isInitialized) {
      await this.initialize();
    }

    try {
      const prompt = this.buildPrompt(request);

      const response = await axios.post(
        `${this.baseUrl}/api/generate`,
        {
          model: this._config.model,
          prompt: prompt,
          stream: false,
          format: 'json',
          options: {
            temperature: this._config.temperature ?? 0.1,
            num_predict: this._config.maxTokens || 4096
          }
        }
      );

      const content = response.data.response || '{}';
      const tokensUsed = this.estimateTokens(content);
      const responseTime = Date.now() - startTime;

      const analysis = this.parseResponse(content);

      // Ollama is self-hosted, so cost is essentially zero
      this.updateStats(responseTime, tokensUsed, 0);

      return {
        id: uuidv4(),
        findings: analysis.findings,
        summary: analysis.summary,
        confidence: this.calculateConfidence(analysis.findings),
        processingTime: responseTime,
        tokensUsed,
        cost: 0
      };
    } catch (error) {
      this.recordError();
      const message = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Ollama analysis failed: ${message}`);
    }
  }

  async validateConfig(): Promise<boolean> {
    try {
      await this.initialize();
      // Check if the specified model is available
      const response = await axios.get(`${this.baseUrl}/api/tags`);
      const models = response.data.models || [];
      const modelExists = models.some((m: any) => m.name === this._config.model);
      return modelExists;
    } catch {
      return false;
    }
  }

  async shutdown(): Promise<void> {
    this._isInitialized = false;
  }

  estimateTokens(text: string): number {
    return Math.ceil(text.length / 4);
  }

  calculateCost(tokens: number): number {
    // Ollama is self-hosted, cost is negligible
    return 0;
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
