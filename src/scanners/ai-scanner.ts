import { ScannerEngine as BaseScannerEngine } from '../core/scanner-engine';
import { AIManager, AIAnalysisRequest } from '../ai';
import { ScanOptions, ScanResult, SecurityFinding, ReportData, EnhancedScanResult } from '../types';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';

export class AIScannerEngine extends BaseScannerEngine {
  private aiManager: AIManager | null = null;
  private enableAI: boolean = false;
  private aiCostLimit?: number;

  constructor(aiManager?: AIManager, options?: { enableAI?: boolean; costLimit?: number }) {
    super();
    this.aiManager = aiManager || null;
    this.enableAI = options?.enableAI || false;
    this.aiCostLimit = options?.costLimit;
  }

  setAIManager(manager: AIManager): void {
    this.aiManager = manager;
  }

  setEnableAI(enabled: boolean): void {
    this.enableAI = enabled;
  }

  setCostLimit(limit?: number): void {
    this.aiCostLimit = limit;
  }

  public async scan(options: ScanOptions): Promise<ReportData> {
    // First, run the base static analysis
    const report = await super.scan(options);

    // Check if AI analysis should be enabled
    const aiEnabled = options.enableAiAnalysis || this.enableAI;
    if (!aiEnabled || !this.aiManager) {
      return report;
    }

    console.log('🤖 Starting AI-enhanced security analysis...');

    try {
      // Get the most critical files to analyze with AI
      const filesToAnalyze = this.selectFilesForAIAnalysis(report.results);

      console.log(`📝 Selected ${filesToAnalyze.length} files for AI analysis`);

      // Prepare AI analysis requests
      const aiRequests = await this.prepareAIRequests(filesToAnalyze, options);

      // Run AI analysis
      const aiResults = await this.aiManager.analyzeBatch(aiRequests);

      // Merge AI results with static findings
      const enhancedResults = this.mergeAIResults(report.results, filesToAnalyze, aiResults);

      // Generate updated report
      const enhancedReport = this.generateEnhancedReport(enhancedResults);

      // Log AI usage statistics
      this.logAIUsage();

      return enhancedReport;
    } catch (error) {
      console.error('AI analysis failed:', error);
      // Return the original report if AI fails
      return report;
    }
  }

  private selectFilesForAIAnalysis(results: ScanResult[]): ScanResult[] {
    // Prioritize files with findings, especially high severity
    const filesWithFindings = results.filter(r => r.findings.length > 0);

    // Sort by severity of findings
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    
    filesWithFindings.sort((a, b) => {
      const aMaxSeverity = Math.min(...a.findings.map(f => severityOrder[f.severity as keyof typeof severityOrder] || 4));
      const bMaxSeverity = Math.min(...b.findings.map(f => severityOrder[f.severity as keyof typeof severityOrder] || 4));
      return aMaxSeverity - bMaxSeverity;
    });

    // Limit to most important files (prevent excessive API calls)
    const maxFiles = 10;
    return filesWithFindings.slice(0, maxFiles);
  }

  private async prepareAIRequests(files: ScanResult[], options: ScanOptions): Promise<AIAnalysisRequest[]> {
    const requests: AIAnalysisRequest[] = [];

    for (const file of files) {
      try {
        const content = fs.readFileSync(file.filePath, 'utf-8');
        const language = this.detectLanguage(file.fileType);

        // Truncate large files
        const maxChars = 10000;
        const codeSnippet = content.length > maxChars 
          ? content.substring(0, maxChars) + '\n... [truncated]'
          : content;

        requests.push({
          codeSnippet,
          filePath: file.filePath,
          fileType: file.fileType,
          language,
          context: `Existing findings: ${file.findings.map(f => f.message).join('; ')}`,
          scanOptions: {
            enableOwasp: options.enableOwasp || true,
            enableSecrets: options.enableSecrets || true,
            enableInfrastructure: file.fileType.includes('infrastructure')
          }
        });
      } catch (error) {
        console.warn(`Could not read file ${file.filePath}:`, error);
      }
    }

    return requests;
  }

  private mergeAIResults(
    originalResults: ScanResult[],
    analyzedFiles: ScanResult[],
    aiResults: (import('../ai').AIAnalysisResult | null)[]
  ): EnhancedScanResult[] {
    const resultsMap = new Map<string, EnhancedScanResult>();

    // Initialize with original results
    for (const result of originalResults) {
      resultsMap.set(result.filePath, {
        ...result,
        aiFindings: []
      });
    }

    // Merge AI results
    for (let i = 0; i < analyzedFiles.length; i++) {
      const file = analyzedFiles[i];
      const aiResult = aiResults[i];

      if (!aiResult) continue;

      const enhanced = resultsMap.get(file.filePath);
      if (!enhanced) continue;

      // Convert AI findings to our format
      const aiFindings: SecurityFinding[] = aiResult.findings.map(finding => ({
        id: uuidv4(),
        ruleId: `AI-${finding.category.toUpperCase()}`,
        severity: finding.severity,
        category: finding.category,
        filePath: file.filePath,
        lineNumber: finding.lineStart || 1,
        columnNumber: finding.lineStart ? undefined : 1,
        message: finding.title,
        description: finding.description,
        remediation: finding.remediation,
        references: finding.references,
        confidence: this.mapConfidence(finding.confidence),
        owaspCategory: finding.owaspCategory,
        aiEnhanced: true,
        aiProvider: this.aiManager?.getEnabledProviders()[0]?.name || 'unknown',
        aiConfidence: finding.confidence
      }));

      // Add new findings from AI that aren't duplicates
      const existingMessages = new Set(enhanced.findings.map(f => f.message));
      const uniqueAIFindings = aiFindings.filter(f => !existingMessages.has(f.message));

      enhanced.aiFindings = uniqueAIFindings;
      enhanced.aiAnalysis = {
        provider: this.aiManager?.getEnabledProviders()[0]?.name || 'unknown',
        model: 'unknown',
        tokensUsed: aiResult.tokensUsed || 0,
        cost: aiResult.cost || 0,
        processingTime: aiResult.processingTime,
        timestamp: new Date()
      };
    }

    return Array.from(resultsMap.values());
  }

  private mapConfidence(aiConfidence: number): 'high' | 'medium' | 'low' {
    if (aiConfidence >= 0.8) return 'high';
    if (aiConfidence >= 0.5) return 'medium';
    return 'low';
  }

  private detectLanguage(fileType: string): string {
    const languageMap: Record<string, string> = {
      'javascript': 'JavaScript',
      'typescript': 'TypeScript',
      'python': 'Python',
      'java': 'Java',
      'csharp': 'C#',
      'go': 'Go',
      'rust': 'Rust',
      'ruby': 'Ruby',
      'php': 'PHP',
      'sql': 'SQL',
      'yaml': 'YAML',
      'json': 'JSON',
      'xml': 'XML',
      'dockerfile': 'Dockerfile',
      'terraform': 'Terraform',
      'kubernetes': 'Kubernetes'
    };

    return languageMap[fileType] || 'unknown';
  }

  private generateEnhancedReport(results: EnhancedScanResult[]): ReportData {
    const findingsBySeverity: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    const findingsByCategory: Record<string, number> = {};
    const findingsByOwasp: Record<string, number> = {};

    let totalFindings = 0;
    let aiFindingsCount = 0;
    const allFindings: SecurityFinding[] = [];

    for (const result of results) {
      // Combine static and AI findings
      const combinedFindings = [...result.findings, ...(result.aiFindings || [])];
      
      for (const finding of combinedFindings) {
        totalFindings++;
        findingsBySeverity[finding.severity]++;
        allFindings.push(finding);

        if (finding.aiEnhanced) {
          aiFindingsCount++;
        }

        const category = finding.category;
        findingsByCategory[category] = (findingsByCategory[category] || 0) + 1;

        if (finding.owaspCategory) {
          findingsByOwasp[finding.owaspCategory] = (findingsByOwasp[finding.owaspCategory] || 0) + 1;
        }
      }
    }

    // Sort findings by severity
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    allFindings.sort((a, b) => {
      return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
    });

    const summary = this.generateSummary(totalFindings, findingsBySeverity as Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>, aiFindingsCount);

    // Convert EnhancedScanResult to ScanResult for ReportData
    const scanResults: ScanResult[] = results.map(r => ({
      filePath: r.filePath,
      fileType: r.fileType,
      findings: [...r.findings, ...(r.aiFindings || [])],
      scanDuration: r.scanDuration,
      scannedAt: r.scannedAt,
      scannerVersion: r.scannerVersion
    }));

    return {
      scanId: `scan-${Date.now()}`,
      scannedAt: new Date(),
      totalFiles: results.length,
      totalFindings,
      findingsBySeverity: findingsBySeverity as Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>,
      findingsByCategory,
      findingsByOwasp,
      results: scanResults,
      summary
    };
  }

  private generateSummary(
    totalFindings: number, 
    findingsBySeverity: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>,
    aiFindingsCount: number
  ): string {
    if (totalFindings === 0) {
      return '✅ No security issues found! Great job!';
    }

    const parts: string[] = [
      `🔍 Found ${totalFindings} security issue${totalFindings !== 1 ? 's' : ''}:`
    ];

    if (findingsBySeverity.critical > 0) {
      parts.push(`  🚨 ${findingsBySeverity.critical} critical`);
    }
    if (findingsBySeverity.high > 0) {
      parts.push(`  ⚠️  ${findingsBySeverity.high} high`);
    }
    if (findingsBySeverity.medium > 0) {
      parts.push(`  ⚡ ${findingsBySeverity.medium} medium`);
    }
    if (findingsBySeverity.low > 0) {
      parts.push(`  ℹ️  ${findingsBySeverity.low} low`);
    }
    if (findingsBySeverity.info > 0) {
      parts.push(`  📝 ${findingsBySeverity.info} info`);
    }

    if (aiFindingsCount > 0) {
      parts.push(`\n🤖 AI-enhanced analysis found ${aiFindingsCount} additional issues`);
    }

    return parts.join('\n');
  }

  private logAIUsage(): void {
    if (!this.aiManager) return;

    const stats = this.aiManager.getGlobalUsageStats();
    const costs = this.aiManager.getProviderCosts();

    console.log('\n🤖 AI Usage Statistics:');
    for (const [name, stat] of Object.entries(stats)) {
      console.log(`  ${name}:`);
      console.log(`    - Requests: ${stat.totalRequests}`);
      console.log(`    - Tokens: ${stat.totalTokens}`);
      console.log(`    - Cost: $${stat.totalCost.toFixed(4)}`);
      console.log(`    - Avg Response Time: ${stat.averageResponseTime.toFixed(2)}ms`);
    }

    console.log(`\n💰 Total AI Cost: $${this.aiManager.getTotalCost().toFixed(4)}`);
  }
}

// Factory function for easy initialization
export function createAIScanner(options?: {
  aiConfigPath?: string;
  enableAI?: boolean;
  costLimit?: number;
}): AIScannerEngine {
  const aiManager = new AIManager();
  
  return new AIScannerEngine(aiManager, {
    enableAI: options?.enableAI || false,
    costLimit: options?.costLimit
  });
}