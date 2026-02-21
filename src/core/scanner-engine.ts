import { FileDetector } from './file-detector';
import { SQLScanner } from '../scanners/sql';
import { ConfigScanner } from '../scanners/config';
import { InfrastructureScanner } from '../scanners/infrastructure';
import { MarkupScanner } from '../scanners/markup';
import { DataScanner } from '../scanners/data';
import { SourceCodeScanner } from '../scanners/source';
import {
  ScanOptions,
  ScanResult,
  SecurityFinding,
  ReportData,
  SeverityLevel
} from '../types';

export class ScannerEngine {
  private fileDetector: FileDetector;
  private scanners: Map<string, unknown>;

  constructor() {
    this.fileDetector = new FileDetector();
    this.scanners = new Map();
    this.initializeScanners();
  }

  private initializeScanners(): void {
    this.scanners.set('sql-scanner', new SQLScanner());
    this.scanners.set('config-scanner', new ConfigScanner());
    this.scanners.set('infrastructure-scanner', new InfrastructureScanner());
    this.scanners.set('markup-scanner', new MarkupScanner());
    this.scanners.set('data-scanner', new DataScanner());
    this.scanners.set('source-scanner', new SourceCodeScanner());
  }

  public async scan(options: ScanOptions): Promise<ReportData> {
    const {
      directory,
      includeExtensions,
      excludeExtensions,
      excludePaths = [],
      parallel = true,
      maxWorkers = 4
    } = options;

    console.log(`🔍 Starting security scan of: ${directory}`);
    console.log(`📁 Scan options: ${JSON.stringify({
      includeExtensions: includeExtensions || 'all',
      excludeExtensions: excludeExtensions || 'none',
      excludePaths: excludePaths.join(', ') || 'none',
      parallel,
      maxWorkers
    })}`);

    // Get all files to scan
    const files = this.fileDetector.getFilesToScan(
      directory,
      includeExtensions,
      excludeExtensions,
      excludePaths
    );

    console.log(`📄 Found ${files.length} files to scan`);

    // Scan files
    const results: ScanResult[] = [];

    if (parallel) {
      // Process files in batches for parallel execution
      const batches = this.createBatches(files, maxWorkers);
      for (const batch of batches) {
        const batchResults = await Promise.all(
          batch.map(file => this.scanFile(file))
        );
        results.push(...batchResults);
      }
    } else {
      // Sequential processing
      for (const file of files) {
        const result = await this.scanFile(file);
        results.push(result);
      }
    }

    // Generate report
    return this.generateReport(results);
  }

  private createBatches<T>(items: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  private async scanFile(filePath: string): Promise<ScanResult> {
    const detection = this.fileDetector.detectFileType(filePath);
    const scannerName = this.fileDetector.getScannerForFileType(detection.detectedType);

    if (!scannerName) {
      // No specific scanner for this file type, return empty result
      return {
        filePath,
        fileType: detection.detectedType,
        findings: [],
        scanDuration: 0,
        scannedAt: new Date(),
        scannerVersion: '1.0.0'
      };
    }

    const scanner = this.scanners.get(scannerName);
    if (!scanner) {
      return {
        filePath,
        fileType: detection.detectedType,
        findings: [],
        scanDuration: 0,
        scannedAt: new Date(),
        scannerVersion: '1.0.0'
      };
    }

    try {
      // Type assertion needed due to dynamic scanner loading
      const scanMethod = (scanner as { scan: (path: string) => Promise<ScanResult> }).scan;
      return await scanMethod(filePath);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error(`Error scanning ${filePath}:`, errorMessage);

      return {
        filePath,
        fileType: detection.detectedType,
        findings: [{
          id: `scan-error-${Date.now()}`,
          ruleId: 'SCAN-ERROR',
          severity: 'info' as SeverityLevel,
          category: 'input-validation',
          filePath,
          lineNumber: 0,
          message: `Scanning error: ${errorMessage}`,
          description: 'An error occurred while scanning this file',
          confidence: 'low'
        }],
        scanDuration: 0,
        scannedAt: new Date(),
        scannerVersion: '1.0.0'
      };
    }
  }

  private generateReport(results: ScanResult[]): ReportData {
    const findingsBySeverity: Record<SeverityLevel, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    const findingsByCategory: Record<string, number> = {};
    const findingsByOwasp: Record<string, number> = {};

    let totalFindings = 0;
    const allFindings: SecurityFinding[] = [];

    for (const result of results) {
      for (const finding of result.findings) {
        totalFindings++;
        findingsBySeverity[finding.severity]++;
        allFindings.push(finding);

        // Category counts
        const category = finding.category;
        findingsByCategory[category] = (findingsByCategory[category] || 0) + 1;

        // OWASP counts
        if (finding.owaspCategory) {
          findingsByOwasp[finding.owaspCategory] = (findingsByOwasp[finding.owaspCategory] || 0) + 1;
        }
      }
    }

    // Sort findings by severity
    const severityOrder: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info'];
    allFindings.sort((a, b) => {
      return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
    });

    // Generate summary
    const summary = this.generateSummary(totalFindings, findingsBySeverity);

    return {
      scanId: `scan-${Date.now()}`,
      scannedAt: new Date(),
      totalFiles: results.length,
      totalFindings,
      findingsBySeverity,
      findingsByCategory: findingsByCategory as Record<string, number>,
      findingsByOwasp: findingsByOwasp as Record<string, number>,
      results,
      summary
    };
  }

  private generateSummary(totalFindings: number, findingsBySeverity: Record<SeverityLevel, number>): string {
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

    return parts.join('\n');
  }

  public generateMarkdownReport(report: ReportData): string {
    const lines: string[] = [
      '# 🔒 Security Scan Report',
      '',
      `**Scan ID:** ${report.scanId}`,
      `**Scanned At:** ${report.scannedAt.toISOString()}`,
      `**Total Files Scanned:** ${report.totalFiles}`,
      `**Total Findings:** ${report.totalFindings}`,
      '',
      '## 📊 Summary',
      '',
      '```',
      report.summary,
      '```',
      '',
      '## 🔴 Findings by Severity',
      '',
      '| Severity | Count |',
      '|----------|-------|',
      `| Critical | ${report.findingsBySeverity.critical} |`,
      `| High | ${report.findingsBySeverity.high} |`,
      `| Medium | ${report.findingsBySeverity.medium} |`,
      `| Low | ${report.findingsBySeverity.low} |`,
      `| Info | ${report.findingsBySeverity.info} |`,
      '',
      '## 📋 Detailed Findings',
      ''
    ];

    // Group findings by file
    const findingsByFile = new Map<string, SecurityFinding[]>();
    for (const result of report.results) {
      if (result.findings.length > 0) {
        findingsByFile.set(result.filePath, result.findings);
      }
    }

    for (const [filePath, findings] of findingsByFile) {
      lines.push(`### ${filePath}`);
      lines.push('');

      for (const finding of findings) {
        const severityEmoji = this.getSeverityEmoji(finding.severity);
        lines.push(`#### ${severityEmoji} ${finding.ruleId}: ${finding.message}`);
        lines.push('');
        lines.push(`- **Severity:** ${finding.severity.toUpperCase()}`);
        lines.push(`- **Category:** ${finding.category}`);
        if (finding.owaspCategory) {
          lines.push(`- **OWASP:** ${finding.owaspCategory}`);
        }
        lines.push(`- **Line:** ${finding.lineNumber}`);
        if (finding.columnNumber) {
          lines.push(`- **Column:** ${finding.columnNumber}`);
        }
        lines.push('');
        lines.push(`**Description:** ${finding.description}`);
        lines.push('');

        if (finding.remediation) {
          lines.push(`**Remediation:** ${finding.remediation}`);
          lines.push('');
        }

        if (finding.codeSnippet) {
          lines.push('**Code:**');
          lines.push('```');
          lines.push(finding.codeSnippet);
          lines.push('```');
          lines.push('');
        }

        if (finding.references && finding.references.length > 0) {
          lines.push('**References:**');
          for (const ref of finding.references) {
            lines.push(`- ${ref}`);
          }
          lines.push('');
        }

        lines.push('---');
        lines.push('');
      }
    }

    return lines.join('\n');
  }

  public generateSARIFReport(report: ReportData): string {
    const sarif = {
      $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'PR Security Scanner',
            version: '1.0.0',
            informationUri: 'https://github.com/security-scanner',
            rules: this.extractRules(report)
          }
        },
        results: this.extractResults(report),
        invocations: [{
          executionSuccessful: true,
          startTimeUtc: report.scannedAt.toISOString()
        }]
      }]
    };

    return JSON.stringify(sarif, null, 2);
  }

  private extractRules(report: ReportData): unknown[] {
    const rules = new Map();

    for (const result of report.results) {
      for (const finding of result.findings) {
        if (!rules.has(finding.ruleId)) {
          rules.set(finding.ruleId, {
            id: finding.ruleId,
            name: finding.message,
            shortDescription: { text: finding.message },
            fullDescription: { text: finding.description },
            defaultConfiguration: {
              level: this.severityToSARIFLevel(finding.severity)
            },
            properties: {
              category: finding.category,
              owaspCategory: finding.owaspCategory
            }
          });
        }
      }
    }

    return Array.from(rules.values());
  }

  private extractResults(report: ReportData): unknown[] {
    return report.results.flatMap(result =>
      result.findings.map(finding => ({
        ruleId: finding.ruleId,
        level: this.severityToSARIFLevel(finding.severity),
        message: { text: finding.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: finding.filePath },
            region: {
              startLine: finding.lineNumber,
              startColumn: finding.columnNumber || 1
            }
          }
        }],
        properties: {
          category: finding.category,
          owaspCategory: finding.owaspCategory,
          remediation: finding.remediation,
          confidence: finding.confidence
        }
      }))
    );
  }

  private severityToSARIFLevel(severity: SeverityLevel): string {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
      case 'info':
      default:
        return 'note';
    }
  }

  private getSeverityEmoji(severity: SeverityLevel): string {
    switch (severity) {
      case 'critical': return '🚨';
      case 'high': return '⚠️';
      case 'medium': return '⚡';
      case 'low': return 'ℹ️';
      case 'info': return '📝';
      default: return '❓';
    }
  }
}
