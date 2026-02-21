import * as fs from 'fs';
import {
  SecurityFinding,
  ScanResult,
  SeverityLevel,
  SecurityCategory,
  OwaspCategory,
  ConfidenceLevel
} from '../../types';
import { SQL_INJECTION_PATTERNS, SQL_SECURITY_RULES } from '../../rules/sql/injection-patterns';
import { SECRET_PATTERNS, EXCLUDED_PATHS } from '../../rules/secrets/patterns';

export class SQLScanner {
  private name = 'SQL Scanner';
  private version = '1.0.0';

  public async scan(filePath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      // Check for SQL injection patterns
      findings.push(...this.detectSQLInjection(content, lines, filePath));

      // Check for hardcoded credentials
      findings.push(...this.detectHardcodedCredentials(content, lines, filePath));

      // Check for dangerous SQL functions
      findings.push(...this.detectDangerousFunctions(content, lines, filePath));

      // Check for secrets in SQL
      findings.push(...this.detectSecrets(content, lines, filePath));

      // Check for SQL security rules
      findings.push(...this.checkSecurityRules(content, lines, filePath));

    } catch (error) {
      findings.push({
        id: `sql-error-${Date.now()}`,
        ruleId: 'SQL-ERROR',
        severity: 'info' as SeverityLevel,
        category: 'input-validation' as SecurityCategory,
        filePath,
        lineNumber: 0,
        message: `Error scanning file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        description: 'An error occurred while scanning the file',
        confidence: 'low' as ConfidenceLevel
      });
    }

    return {
      filePath,
      fileType: 'sql',
      findings,
      scanDuration: Date.now() - startTime,
      scannedAt: new Date(),
      scannerVersion: this.version
    };
  }

  private detectSQLInjection(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    SQL_INJECTION_PATTERNS.forEach((pattern, index) => {
      const regex = new RegExp(pattern.pattern.source, 'gi');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        // Check if this might be a false positive
        if (this.isPotentialFalsePositive(codeSnippet, pattern.context)) {
          continue;
        }

        findings.push({
          id: `sql-inj-${index}-${match.index}`,
          ruleId: `SQL-INJ-${index.toString().padStart(3, '0')}`,
          severity: pattern.severity,
          category: 'sql-injection' as SecurityCategory,
          owaspCategory: 'A03:2021-Injection' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: `Potential SQL injection pattern detected (${pattern.context.join(', ')})`,
          description: `Detected SQL injection pattern for dialects: ${pattern.dialect.join(', ')}. ` +
                      'This could allow attackers to execute arbitrary SQL commands.',
          remediation: 'Use parameterized queries or prepared statements instead of string concatenation.',
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'medium' as ConfidenceLevel,
          metadata: {
            dialect: pattern.dialect,
            context: pattern.context,
            matchedPattern: pattern.pattern.source
          }
        });
      }
    });

    return findings;
  }

  private detectHardcodedCredentials(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const credentialPatterns = [
      {
        pattern: /IDENTIFIED\s+BY\s+['"]([^'"]+)['"]/gi,
        type: 'MySQL/MariaDB'
      },
      {
        pattern: /WITH\s+PASSWORD\s+['"]([^'"]+)['"]/gi,
        type: 'PostgreSQL'
      },
      {
        pattern: /PASSWORD\s*=\s*['"]([^'"]+)['"]/gi,
        type: 'Generic'
      },
      {
        pattern: /CREATE\s+USER\s+\w+\s+PASSWORD\s+['"]([^'"]+)['"]/gi,
        type: 'PostgreSQL'
      },
      {
        pattern: /GRANT\s+.*\s+TO\s+\w+\s+IDENTIFIED\s+BY\s+['"]([^'"]+)['"]/gi,
        type: 'MySQL'
      }
    ];

    credentialPatterns.forEach(({ pattern, type }) => {
      let match: RegExpExecArray | null;

      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        // Skip if it looks like a placeholder
        if (this.isPlaceholder(match[1])) {
          continue;
        }

        findings.push({
          id: `sql-cred-${match.index}`,
          ruleId: 'SQL-HARDCODED-CREDENTIALS',
          severity: 'critical' as SeverityLevel,
          category: 'hardcoded-secrets' as SecurityCategory,
          owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: `Hardcoded ${type} credentials detected`,
          description: `Database credentials are hardcoded in the SQL file. This is a critical security risk as credentials can be exposed through version control.`,
          remediation: 'Use environment variables, configuration files, or secret management tools for credentials. Never hardcode passwords in SQL files.',
          codeSnippet: this.maskSensitiveData(codeSnippet),
          confidence: 'high' as ConfidenceLevel,
          metadata: {
            credentialType: type
          }
        });
      }
    });

    return findings;
  }

  private detectDangerousFunctions(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const dangerousFunctions = [
      {
        pattern: /xp_cmdshell/gi,
        name: 'xp_cmdshell',
        severity: 'critical' as SeverityLevel,
        description: 'Extended stored procedure for executing OS commands',
        remediation: 'Avoid xp_cmdshell. Use SQL Server Agent jobs or application-level code instead.'
      },
      {
        pattern: /xp_regread/gi,
        name: 'xp_regread',
        severity: 'high' as SeverityLevel,
        description: 'Extended stored procedure for reading registry',
        remediation: 'Avoid registry access from SQL. Use configuration tables instead.'
      },
      {
        pattern: /xp_regwrite/gi,
        name: 'xp_regwrite',
        severity: 'critical' as SeverityLevel,
        description: 'Extended stored procedure for writing to registry',
        remediation: 'Never allow SQL to modify registry. Use proper configuration management.'
      },
      {
        pattern: /LOAD_FILE\s*\(/gi,
        name: 'LOAD_FILE',
        severity: 'high' as SeverityLevel,
        description: 'MySQL function to read files',
        remediation: 'Restrict file_priv and use secure_file_priv setting.'
      },
      {
        pattern: /INTO\s+OUTFILE/gi,
        name: 'INTO OUTFILE',
        severity: 'critical' as SeverityLevel,
        description: 'MySQL syntax for writing files',
        remediation: 'Restrict file_priv and monitor for suspicious file write activity.'
      },
      {
        pattern: /UTL_HTTP\./gi,
        name: 'UTL_HTTP',
        severity: 'high' as SeverityLevel,
        description: 'Oracle package for HTTP requests',
        remediation: 'Remove UTL_HTTP privileges from public and application users.'
      },
      {
        pattern: /UTL_FILE\./gi,
        name: 'UTL_FILE',
        severity: 'high' as SeverityLevel,
        description: 'Oracle package for file I/O',
        remediation: 'Configure UTL_FILE_DIR carefully and restrict access.'
      }
    ];

    dangerousFunctions.forEach(func => {
      let match: RegExpExecArray | null;

      while ((match = func.pattern.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `sql-danger-${func.name}-${match.index}`,
          ruleId: `SQL-DANGEROUS-${func.name.toUpperCase()}`,
          severity: func.severity,
          category: 'sql-injection' as SecurityCategory,
          owaspCategory: 'A03:2021-Injection' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: `Dangerous SQL function detected: ${func.name}`,
          description: func.description,
          remediation: func.remediation,
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    });

    return findings;
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
          id: `sql-secret-${secretPattern.name}-${match.index}`,
          ruleId: 'SQL-SECRET',
          severity: secretPattern.severity,
          category: 'hardcoded-secrets' as SecurityCategory,
          owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: secretPattern.description,
          description: `Detected potential ${secretPattern.name} in SQL file. Secrets should never be stored in database scripts.`,
          remediation: 'Remove hardcoded secrets and use secure secret management solutions.',
          codeSnippet: this.maskSensitiveData(codeSnippet),
          confidence: 'medium' as ConfidenceLevel,
          metadata: {
            secretType: secretPattern.name,
            category: secretPattern.category
          }
        });
      }
    });

    return findings;
  }

  private checkSecurityRules(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const rule of SQL_SECURITY_RULES) {
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

  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }

  private getLineStartIndex(content: string, lineNumber: number): number {
    const lines = content.split('\n');
    let index = 0;
    for (let i = 0; i < lineNumber - 1; i++) {
      index += lines[i].length + 1; // +1 for newline
    }
    return index;
  }

  private isPotentialFalsePositive(codeSnippet: string, contexts: string[]): boolean {
    const falsePositiveIndicators = [
      /\/\/.*/, // Comment
      /\/\*[\s\S]*?\*\//, // Block comment
      /^\s*--/, // SQL comment
      /^\s*#/, // Hash comment
      /test|spec|example|sample|demo/i, // Test files
      /placeholder|changeme|your_|xxx/i, // Placeholder values
      /process\.env\./, // Environment variable
      /\$\{process\.env\./, // Template env var
      /config\./, // Config reference
    ];

    return falsePositiveIndicators.some(pattern => pattern.test(codeSnippet));
  }

  private isPlaceholder(value: string): boolean {
    const placeholderPatterns = [
      /^(password|pass|pwd|secret|key|token)$/i,
      /^(your_|my_|the_)/i,
      /^(change|replace|enter|set)_/i,
      /^(xxx|yyy|zzz|aaa|bbb|ccc)+$/i,
      /\$\{.*\}/, // Template literal
      /\$\w+/, // Shell variable
      /^<.*>$/, // XML-style placeholder
    ];

    return placeholderPatterns.some(pattern => pattern.test(value));
  }

  private maskSensitiveData(codeSnippet: string): string {
    // Mask potential passwords, tokens, and keys
    return codeSnippet
      .replace(/password\s*=\s*["'][^"']{4,}["']/gi, 'password="***MASKED***"')
      .replace(/token\s*=\s*["'][^"']{8,}["']/gi, 'token="***MASKED***"')
      .replace(/key\s*=\s*["'][^"']{8,}["']/gi, 'key="***MASKED***"')
      .replace(/secret\s*=\s*["'][^"']{8,}["']/gi, 'secret="***MASKED***"')
      .replace(/BY\s+["'][^"']{4,}["']/gi, 'BY "***MASKED***"');
  }
}
