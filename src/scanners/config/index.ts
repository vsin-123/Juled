import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'yaml';
import { XMLParser } from 'fast-xml-parser';
import * as ini from 'ini';
import JSON5 from 'json5';
import {
  SecurityFinding,
  ScanResult,
  SeverityLevel,
  SecurityCategory,
  OwaspCategory,
  ConfidenceLevel
} from '../../types';
import { SECRET_PATTERNS, EXCLUDED_PATHS } from '../../rules/secrets/patterns';
import { ALL_OWASP_RULES } from '../../rules/owasp/top10-rules';

export class ConfigScanner {
  private name = 'Config Scanner';
  private version = '1.0.0';

  public async scan(filePath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];
    const extension = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath).toLowerCase();

    try {
      const content = fs.readFileSync(filePath, 'utf-8');

      // Detect file type and parse accordingly
      if (this.isJSON(extension, basename, content)) {
        findings.push(...await this.scanJSON(content, filePath));
      } else if (this.isYAML(extension, basename, content)) {
        findings.push(...await this.scanYAML(content, filePath));
      } else if (this.isXML(extension, basename, content)) {
        findings.push(...await this.scanXML(content, filePath));
      } else if (this.isINI(extension, basename)) {
        findings.push(...await this.scanINI(content, filePath));
      } else if (this.isProperties(extension, basename, content)) {
        findings.push(...await this.scanProperties(content, filePath));
      } else {
        // Generic text-based scan
        findings.push(...this.scanGeneric(content, filePath));
      }

    } catch (error) {
      findings.push({
        id: `config-error-${Date.now()}`,
        ruleId: 'CONFIG-ERROR',
        severity: 'info' as SeverityLevel,
        category: 'input-validation' as SecurityCategory,
        filePath,
        lineNumber: 0,
        message: `Error scanning file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        description: 'An error occurred while parsing the configuration file',
        confidence: 'low' as ConfidenceLevel
      });
    }

    return {
      filePath,
      fileType: this.detectFileType(extension, path.basename(filePath)),
      findings,
      scanDuration: Date.now() - startTime,
      scannedAt: new Date(),
      scannerVersion: this.version
    };
  }

  private isJSON(ext: string, basename: string, content: string): boolean {
    return ext === '.json' || ext === '.jsonc' ||
           (content.trim().startsWith('{') && content.trim().endsWith('}')) ||
           (content.trim().startsWith('[') && content.trim().endsWith(']'));
  }

  private isYAML(ext: string, basename: string, content: string): boolean {
    return ext === '.yml' || ext === '.yaml' ||
           /^---\s*$/m.test(content) ||
           /^\w+:\s/m.test(content);
  }
  
  private isXML(ext: string, basename: string, content: string): boolean {
    return ext === '.xml' || ext === '.xsd' || ext === '.wsdl' ||
           content.trim().startsWith('<?xml') ||
           content.trim().startsWith('<');
  }

  private isINI(ext: string, basename: string): boolean {
    return ext === '.ini' || ext === '.cfg' || ext === '.conf' || ext === '.cnf' || ext === '.prefs';
  }

  private isProperties(ext: string, basename: string, content: string): boolean {
    return ext === '.properties' ||
           basename.startsWith('.env') ||
           /^\w+[\.\w]*\s*=\s*.+$/m.test(content);
  }

  private detectFileType(ext: string, basename: string): string {
    if (ext === '.json') return 'json';
    if (ext === '.yml' || ext === '.yaml') return 'yaml';
    if (ext === '.xml') return 'xml';
    if (ext === '.ini' || ext === '.cfg' || ext === '.conf') return 'ini';
    if (ext === '.properties' || basename.startsWith('.env')) return 'properties';
    return 'config';
  }

  private async scanJSON(content: string, filePath: string): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const lines = content.split('\n');

    try {
      const data = JSON5.parse(content);
      findings.push(...this.scanObject(data, filePath, lines, 'json'));
    } catch {
      // Invalid JSON, scan as text
      findings.push(...this.scanGeneric(content, filePath));
    }

    findings.push(...this.checkSecurityRules(content, lines, filePath));

    return findings;
  }

  private async scanYAML(content: string, filePath: string): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const lines = content.split('\n');

    try {
      const data = yaml.parse(content);
      findings.push(...this.scanObject(data, filePath, lines, 'yaml'));
    } catch {
      // Invalid YAML, scan as text
      findings.push(...this.scanGeneric(content, filePath));
    }

    findings.push(...this.checkSecurityRules(content, lines, filePath));

    return findings;
  }

  private async scanXML(content: string, filePath: string): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const lines = content.split('\n');

    try {
      const parser = new XMLParser({
        ignoreAttributes: false,
        parseAttributeValue: true
      });
      const data = parser.parse(content);
      findings.push(...this.scanObject(data, filePath, lines, 'xml'));
    } catch {
      // Invalid XML, scan as text
      findings.push(...this.scanGeneric(content, filePath));
    }

    findings.push(...this.checkSecurityRules(content, lines, filePath));

    return findings;
  }

  private async scanINI(content: string, filePath: string): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const lines = content.split('\n');

    try {
      const data = ini.parse(content);
      findings.push(...this.scanObject(data, filePath, lines, 'ini'));
    } catch {
      // Invalid INI, scan as text
      findings.push(...this.scanGeneric(content, filePath));
    }

    findings.push(...this.checkSecurityRules(content, lines, filePath));

    return findings;
  }

  private async scanProperties(content: string, filePath: string): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const lines = content.split('\n');

    // Properties files are key=value pairs
    lines.forEach((line, index) => {
      // Check for secrets in properties
      SECRET_PATTERNS.forEach(secretPattern => {
        const regex = new RegExp(secretPattern.pattern.source, 'gi');
        if (regex.test(line)) {
          findings.push({
            id: `prop-secret-${index}`,
            ruleId: 'PROP-SECRET',
            severity: secretPattern.severity,
            category: 'hardcoded-secrets' as SecurityCategory,
            owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
            filePath,
            lineNumber: index + 1,
            message: secretPattern.description,
            description: `Potential ${secretPattern.name} found in properties file.`,
            remediation: 'Use environment variables or secure secret management tools.',
            codeSnippet: this.maskSensitiveData(line.trim()),
            confidence: 'medium' as ConfidenceLevel
          });
        }
      });
    });

    findings.push(...this.checkSecurityRules(content, lines, filePath));

    return findings;
  }

  private scanGeneric(content: string, filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const lines = content.split('\n');

    // Check for secrets line by line
    lines.forEach((line, index) => {
      SECRET_PATTERNS.forEach(secretPattern => {
        const regex = new RegExp(secretPattern.pattern.source, 'gi');
        let match: RegExpExecArray | null;

        while ((match = regex.exec(line)) !== null) {
          findings.push({
            id: `config-secret-${secretPattern.name}-${index}`,
            ruleId: 'CONFIG-SECRET',
            severity: secretPattern.severity,
            category: 'hardcoded-secrets' as SecurityCategory,
            owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
            filePath,
            lineNumber: index + 1,
            columnNumber: match.index + 1,
            message: secretPattern.description,
            description: `Potential ${secretPattern.name} detected in configuration file.`,
            remediation: 'Remove hardcoded secrets and use secure secret management.',
            codeSnippet: this.maskSensitiveData(line.trim()),
            confidence: 'medium' as ConfidenceLevel
          });
        }
      });
    });

    findings.push(...this.checkSecurityRules(content, lines, filePath));

    return findings;
  }

  private scanObject(
    obj: unknown,
    filePath: string,
    lines: string[],
    fileType: string,
    path = ''
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (typeof obj === 'object' && obj !== null) {
      for (const [key, value] of Object.entries(obj)) {
        const currentPath = path ? `${path}.${key}` : key;

        // Check for suspicious keys
        if (this.isSensitiveKey(key)) {
          const lineNumber = this.findLineNumber(lines, key, value);
          const severity = this.getSeverityForKey(key);

          if (typeof value === 'string' && value && !this.isPlaceholder(value)) {
            findings.push({
              id: `config-${fileType}-${currentPath}`,
              ruleId: 'CONFIG-SENSITIVE-DATA',
              severity,
              category: 'hardcoded-secrets' as SecurityCategory,
              owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
              filePath,
              lineNumber,
              message: `Sensitive data found for key "${key}"`,
              description: `Configuration contains potentially sensitive data for key "${key}". This should not be stored in version control.`,
              remediation: 'Move sensitive configuration to environment variables or secret management tools.',
              codeSnippet: this.maskSensitiveData(`${key}: ${value}`),
              confidence: 'high' as ConfidenceLevel,
              metadata: {
                key,
                path: currentPath
              }
            });
          }
        }

        // Recursively scan nested objects
        if (typeof value === 'object' && value !== null) {
          findings.push(...this.scanObject(value, filePath, lines, fileType, currentPath));
        } else if (typeof value === 'string') {
          // Check string values for secrets
          SECRET_PATTERNS.forEach(secretPattern => {
            const regex = new RegExp(secretPattern.pattern.source, 'gi');
            if (regex.test(value)) {
              const lineNumber = this.findLineNumber(lines, key, value);
              findings.push({
                id: `config-value-secret-${key}`,
                ruleId: 'CONFIG-VALUE-SECRET',
                severity: secretPattern.severity,
                category: 'hardcoded-secrets' as SecurityCategory,
                owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
                filePath,
                lineNumber,
                message: secretPattern.description,
                description: `Potential ${secretPattern.name} found in configuration value.`,
                remediation: 'Remove hardcoded secrets and use secure secret management.',
                codeSnippet: this.maskSensitiveData(`${key}: ${value}`),
                confidence: 'medium' as ConfidenceLevel
              });
            }
          });
        }
      }
    }

    return findings;
  }

  private checkSecurityRules(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const rule of ALL_OWASP_RULES) {
      // Only apply rules relevant to config files
      if (!rule.fileTypes.includes('yaml') && !rule.fileTypes.includes('json') &&
          !rule.fileTypes.includes('xml') && !rule.fileTypes.includes('properties')) {
        continue;
      }

      for (const pattern of rule.patterns) {
        const regex = new RegExp(pattern.source, 'gi');
        let match: RegExpExecArray | null;

        while ((match = regex.exec(content)) !== null) {
          const lineNumber = this.getLineNumber(content, match.index);
          const codeSnippet = lines[lineNumber - 1]?.trim() || '';

          // Check negative patterns
          if (rule.negativePatterns) {
            const hasNegativePattern = rule.negativePatterns.some(negPattern =>
              negPattern.test(codeSnippet)
            );
            if (hasNegativePattern) {
              continue;
            }
          }

          findings.push({
            id: `${rule.id}-${match.index}`,
            ruleId: rule.id,
            severity: rule.severity,
            category: rule.category,
            owaspCategory: rule.owaspCategory,
            filePath,
            lineNumber,
            columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
            message: rule.message,
            description: rule.description,
            remediation: rule.remediation,
            codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
            confidence: 'high' as ConfidenceLevel,
            references: rule.references
          });
        }
      }
    }

    return findings;
  }

  private isSensitiveKey(key: string): boolean {
    const sensitivePatterns = [
      /password/i,
      /passwd/i,
      /secret/i,
      /token/i,
      /key/i,
      /api[_-]?key/i,
      /auth/i,
      /credential/i,
      /private/i,
      /cert/i,
      /pin/i,
      /salt/i,
      /hash/i
    ];

    return sensitivePatterns.some(pattern => pattern.test(key));
  }

  private getSeverityForKey(key: string): SeverityLevel {
    if (/password|secret|token|api_key|private_key/i.test(key)) {
      return 'critical';
    }
    if (/auth|credential|cert/i.test(key)) {
      return 'high';
    }
    return 'medium';
  }

  private isPlaceholder(value: string): boolean {
    const placeholderPatterns = [
      /^\$\{.*\}$/, // ${VAR}
      /^\$\w+$/, // $VAR
      /^%.*%$/, // %VAR%
      /^<.*>$/, // <VAR>
      /^(CHANGE|SET|YOUR|MY|PLACEHOLDER)_/i,
      /^(xxx|yyy|zzz|aaa|bbb|ccc)+$/i,
      /^to_be_configured$/i,
      /^null$/i,
      /^undefined$/i,
      /^~$/
    ];

    return placeholderPatterns.some(pattern => pattern.test(value));
  }

  private findLineNumber(lines: string[], key: string, value: unknown): number {
    const searchValue = String(value).substring(0, 50);
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(key) && lines[i].includes(searchValue)) {
        return i + 1;
      }
    }
    return 1;
  }

  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }

  private getLineStartIndex(content: string, lineNumber: number): number {
    const lines = content.split('\n');
    let index = 0;
    for (let i = 0; i < lineNumber - 1; i++) {
      index += lines[i].length + 1;
    }
    return index;
  }

  private maskSensitiveData(line: string): string {
    return line
      .replace(/password["']?\s*[:=]\s*["'][^"']{4,}["']/gi, 'password: "***MASKED***"')
      .replace(/secret["']?\s*[:=]\s*["'][^"']{8,}["']/gi, 'secret: "***MASKED***"')
      .replace(/token["']?\s*[:=]\s*["'][^"']{8,}["']/gi, 'token: "***MASKED***"')
      .replace(/key["']?\s*[:=]\s*["'][^"']{16,}["']/gi, 'key: "***MASKED***"')
      .replace(/AKIA[0-9A-Z]{16}/g, 'AKIA***MASKED***')
      .replace(/[0-9a-zA-Z/+]{40}/g, '***SECRET_KEY_MASKED***');
  }
}
