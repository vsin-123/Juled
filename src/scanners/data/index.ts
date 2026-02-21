import * as fs from 'fs';
import * as path from 'path';
import {
  SecurityFinding,
  ScanResult,
  SeverityLevel,
  SecurityCategory,
  OwaspCategory,
  ConfidenceLevel
} from '../../types';
import { SECRET_PATTERNS } from '../../rules/secrets/patterns';

export class DataScanner {
  private name = 'Data Scanner';
  private version = '1.0.0';

  public async scan(filePath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];

    const extension = path.extname(filePath).toLowerCase();

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      if (extension === '.csv' || extension === '.tsv') {
        findings.push(...this.scanCSV(content, lines, filePath));
      } else if (extension === '.jsonl' || extension === '.ndjson') {
        findings.push(...this.scanJSONL(content, lines, filePath));
      }

      // Always check for secrets
      findings.push(...this.detectSecrets(content, lines, filePath));

    } catch (error) {
      findings.push({
        id: `data-error-${Date.now()}`,
        ruleId: 'DATA-ERROR',
        severity: 'info' as SeverityLevel,
        category: 'data-validation' as SecurityCategory,
        filePath,
        lineNumber: 0,
        message: `Error scanning file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        description: 'An error occurred while scanning the data file',
        confidence: 'low' as ConfidenceLevel
      });
    }

    return {
      filePath,
      fileType: extension === '.csv' || extension === '.tsv' ? 'csv' : 'jsonl',
      findings,
      scanDuration: Date.now() - startTime,
      scannedAt: new Date(),
      scannerVersion: this.version
    };
  }

  private scanCSV(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (lines.length === 0) return findings;

    // Get headers
    const delimiter = content.includes('\t') ? '\t' : ',';
    const headers = lines[0].split(delimiter).map(h => h.trim().toLowerCase());

    // Check for sensitive column headers
    const sensitiveColumns = [
      { pattern: /password|passwd|pwd/i, name: 'password' },
      { pattern: /ssn|social.security/i, name: 'SSN' },
      { pattern: /credit.?card|cc.?num|card.?num/i, name: 'credit card' },
      { pattern: /cvv|ccv|security.?code/i, name: 'CVV' },
      { pattern: /account.?num|acct.?num|iban/i, name: 'account number' },
      { pattern: /dob|birth.?date|date.?of.?birth/i, name: 'date of birth' },
      { pattern: /address|street/i, name: 'address' },
      { pattern: /phone|tel|mobile/i, name: 'phone number' },
      { pattern: /email|e-mail/i, name: 'email' },
      { pattern: /api.?key|secret.?key/i, name: 'API key' },
      { pattern: /token|auth.?token/i, name: 'token' }
    ];

    for (let i = 0; i < headers.length; i++) {
      for (const sensitive of sensitiveColumns) {
        if (sensitive.pattern.test(headers[i])) {
          findings.push({
            id: `csv-sensitive-header-${i}`,
            ruleId: 'CSV-SENSITIVE-HEADER',
            severity: 'medium' as SeverityLevel,
            category: 'data-validation' as SecurityCategory,
            owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
            filePath,
            lineNumber: 1,
            columnNumber: i + 1,
            message: `CSV contains potentially sensitive column: ${headers[i]}`,
            description: `The CSV file contains a column that may hold ${sensitive.name} data. Ensure proper data protection measures are in place.`,
            remediation: 'Review if this data should be in version control. Consider data anonymization or encryption.',
            codeSnippet: `Column ${i + 1}: ${headers[i]}`,
            confidence: 'medium' as ConfidenceLevel,
            metadata: {
              columnIndex: i,
              columnName: headers[i],
              dataType: sensitive.name
            }
          });
        }
      }
    }

    // Check for PII in sample data rows
    const sampleRows = Math.min(lines.length - 1, 10);
    for (let rowIndex = 1; rowIndex <= sampleRows; rowIndex++) {
      const row = lines[rowIndex];
      if (!row) continue;

      const columns = row.split(delimiter);

      for (let colIndex = 0; colIndex < columns.length; colIndex++) {
        const value = columns[colIndex]?.trim() || '';

        // Check for SSN pattern
        if (/^\d{3}-\d{2}-\d{4}$/.test(value) || /^\d{9}$/.test(value)) {
          findings.push({
            id: `csv-ssn-${rowIndex}-${colIndex}`,
            ruleId: 'CSV-PII-SSN',
            severity: 'critical' as SeverityLevel,
            category: 'data-validation' as SecurityCategory,
            owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
            filePath,
            lineNumber: rowIndex + 1,
            columnNumber: colIndex + 1,
            message: 'Potential SSN detected in CSV data',
            description: 'A value matching Social Security Number pattern was found in the CSV.',
            remediation: 'Remove PII from data files or ensure proper encryption and access controls.',
            codeSnippet: `Row ${rowIndex}, Column ${colIndex + 1}: ***REDACTED***`,
            confidence: 'medium' as ConfidenceLevel
          });
        }

        // Check for email pattern
        if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) {
          findings.push({
            id: `csv-email-${rowIndex}-${colIndex}`,
            ruleId: 'CSV-PII-EMAIL',
            severity: 'low' as SeverityLevel,
            category: 'data-validation' as SecurityCategory,
            owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
            filePath,
            lineNumber: rowIndex + 1,
            columnNumber: colIndex + 1,
            message: 'Email address detected in CSV data',
            description: 'Email addresses found in data files may violate privacy policies.',
            remediation: 'Consider anonymizing email addresses or storing separately with access controls.',
            codeSnippet: `Row ${rowIndex}, Column ${colIndex + 1}: ***REDACTED***`,
            confidence: 'high' as ConfidenceLevel
          });
        }

        // Check for credit card pattern
        if (/^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$/.test(value)) {
          findings.push({
            id: `csv-cc-${rowIndex}-${colIndex}`,
            ruleId: 'CSV-PII-CREDITCARD',
            severity: 'critical' as SeverityLevel,
            category: 'data-validation' as SecurityCategory,
            owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
            filePath,
            lineNumber: rowIndex + 1,
            columnNumber: colIndex + 1,
            message: 'Potential credit card number detected',
            description: 'A value matching credit card pattern was found. This is sensitive PCI data.',
            remediation: 'Never store credit card numbers in plain text files. Use PCI compliant storage.',
            codeSnippet: `Row ${rowIndex}, Column ${colIndex + 1}: ***REDACTED***`,
            confidence: 'medium' as ConfidenceLevel
          });
        }
      }
    }

    return findings;
  }

  private scanJSONL(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (let i = 0; i < Math.min(lines.length, 100); i++) {
      const line = lines[i].trim();
      if (!line) continue;

      try {
        const data = JSON.parse(line);
        findings.push(...this.scanObject(data, filePath, i + 1));
      } catch {
        // Invalid JSON line, skip
      }
    }

    return findings;
  }

  private scanObject(obj: unknown, filePath: string, lineNumber: number, path = ''): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (typeof obj === 'object' && obj !== null) {
      for (const [key, value] of Object.entries(obj)) {
        const currentPath = path ? `${path}.${key}` : key;

        // Check for sensitive keys
        if (this.isSensitiveKey(key)) {
          findings.push({
            id: `jsonl-sensitive-${currentPath}`,
            ruleId: 'JSONL-SENSITIVE-KEY',
            severity: 'medium' as SeverityLevel,
            category: 'data-validation' as SecurityCategory,
            owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
            filePath,
            lineNumber,
            message: `Sensitive key detected: ${key}`,
            description: `The data contains a key that may hold sensitive information: ${key}`,
            remediation: 'Review if this data should be in version control. Consider data protection measures.',
            codeSnippet: `${key}: ${typeof value === 'string' ? '***REDACTED***' : value}`,
            confidence: 'medium' as ConfidenceLevel
          });
        }

        // Recursively scan nested objects
        if (typeof value === 'object' && value !== null) {
          findings.push(...this.scanObject(value, filePath, lineNumber, currentPath));
        } else if (typeof value === 'string') {
          // Check string values for PII
          if (/^\d{3}-\d{2}-\d{4}$/.test(value) || /^\d{9}$/.test(value)) {
            findings.push({
              id: `jsonl-ssn-${currentPath}`,
              ruleId: 'JSONL-PII-SSN',
              severity: 'critical' as SeverityLevel,
              category: 'data-validation' as SecurityCategory,
              owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
              filePath,
              lineNumber,
              message: 'Potential SSN detected in data',
              description: `A value matching SSN pattern found at ${currentPath}.`,
              remediation: 'Remove PII from data files or ensure proper encryption.',
              codeSnippet: `${key}: ***REDACTED***`,
              confidence: 'medium' as ConfidenceLevel
            });
          }
        }
      }
    }

    return findings;
  }

  private isSensitiveKey(key: string): boolean {
    const sensitivePatterns = [
      /password/i,
      /secret/i,
      /token/i,
      /key/i,
      /credential/i,
      /ssn/i,
      /social.?security/i,
      /credit.?card/i,
      /cvv/i,
      /account.?num/i
    ];

    return sensitivePatterns.some(pattern => pattern.test(key));
  }

  private detectSecrets(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    SECRET_PATTERNS.forEach(secretPattern => {
      const regex = new RegExp(secretPattern.pattern.source, 'gi');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `data-secret-${secretPattern.name}-${match.index}`,
          ruleId: 'DATA-SECRET',
          severity: secretPattern.severity,
          category: 'hardcoded-secrets' as SecurityCategory,
          owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: secretPattern.description,
          description: `Potential ${secretPattern.name} detected in data file.`,
          remediation: 'Remove secrets from data files and use secure secret management.',
          codeSnippet: this.maskSensitiveData(codeSnippet),
          confidence: 'medium' as ConfidenceLevel
        });
      }
    });

    return findings;
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
      .replace(/\d{3}-\d{2}-\d{4}/g, '***-**-****')
      .replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, '****-****-****-****');
  }
}
