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

export class AzureOpenAIProvider extends BaseAIProvider {
  private apiVersion: string;

  constructor(config: AIProviderConfig) {
    super(config);
    this._config.model = config.model || 'gpt-4';
    this._config.apiVersion = config.apiVersion || '2024-02-15-preview';
    this.apiVersion = this._config.apiVersion;
  }

  async initialize(): Promise<void> {
    if (!this._config.apiKey) {
      throw new Error('Azure OpenAI API key is required');
    }

    if (!this._config.apiEndpoint) {
      throw new Error('Azure OpenAI endpoint is required');
    }

    if (!this._config.deploymentName) {
      throw new Error('Azure OpenAI deployment name is required');
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
      const endpoint = this._config.apiEndpoint!.replace(/\/$/, '');
      const url = `${endpoint}/openai/deployments/${this._config.deploymentName}/chat/completions?api-version=${this.apiVersion}`;

      const response = await axios.post(
        url,
        {
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
          temperature: this._config.temperature ?? 0.1,
          max_tokens: this._config.maxTokens || 4000,
          response_format: { type: 'json_object' }
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'api-key': this._config.apiKey,
            ...this._config.customHeaders
          }
        }
      );

      const content = response.data.choices[0]?.message?.content || '{}';
      const tokensUsed = response.data.usage?.total_tokens || this.estimateTokens(content);
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
      throw new Error(`Azure OpenAI analysis failed: ${message}`);
    }
  }

  async validateConfig(): Promise<boolean> {
    if (!this._config.apiKey || !this._config.apiEndpoint || !this._config.deploymentName) {
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
    return Math.ceil(text.length / 4);
  }

  calculateCost(tokens: number): number {
    // Azure pricing varies, using approximate costs
    const costPer1KTokens = 0.03; // approximate for GPT-4
    return (tokens / 1000) * costPer1KTokens;
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
