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

export class MarkupScanner {
  private name = 'Markup Scanner';
  private version = '1.0.0';

  public async scan(filePath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];

    const extension = path.extname(filePath).toLowerCase();

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      if (extension === '.html' || extension === '.htm') {
        findings.push(...this.scanHTML(content, lines, filePath));
      } else if (extension === '.md' || extension === '.markdown' || extension === '.mdx') {
        findings.push(...this.scanMarkdown(content, lines, filePath));
      }

      // Always check for secrets
      findings.push(...this.detectSecrets(content, lines, filePath));

    } catch (error) {
      findings.push({
        id: `markup-error-${Date.now()}`,
        ruleId: 'MARKUP-ERROR',
        severity: 'info' as SeverityLevel,
        category: 'xss' as SecurityCategory,
        filePath,
        lineNumber: 0,
        message: `Error scanning file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        description: 'An error occurred while scanning the markup file',
        confidence: 'low' as ConfidenceLevel
      });
    }

    return {
      filePath,
      fileType: extension === '.html' || extension === '.htm' ? 'html' : 'markdown',
      findings,
      scanDuration: Date.now() - startTime,
      scannedAt: new Date(),
      scannerVersion: this.version
    };
  }

  private scanHTML(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // XSS vulnerability patterns
    const xssPatterns = [
      {
        pattern: /javascript:/gi,
        message: 'JavaScript protocol detected',
        severity: 'high' as SeverityLevel,
        description: 'javascript: protocol can be used for XSS attacks'
      },
      {
        pattern: /on\w+\s*=\s*["'][^"']*alert\s*\(/gi,
        message: 'Inline event handler with suspicious code',
        severity: 'high' as SeverityLevel,
        description: 'Inline event handlers can lead to XSS vulnerabilities'
      },
      {
        pattern: /eval\s*\(/gi,
        message: 'Eval usage detected',
        severity: 'high' as SeverityLevel,
        description: 'eval() can execute arbitrary code and lead to XSS'
      },
      {
        pattern: /innerHTML\s*=/gi,
        message: 'innerHTML assignment detected',
        severity: 'medium' as SeverityLevel,
        description: 'innerHTML can introduce XSS if user input is not properly sanitized'
      },
      {
        pattern: /document\.write\s*\(/gi,
        message: 'document.write usage detected',
        severity: 'medium' as SeverityLevel,
        description: 'document.write can be used for XSS attacks'
      }
    ];

    for (const check of xssPatterns) {
      const regex = new RegExp(check.pattern.source, 'gi');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `html-xss-${match.index}`,
          ruleId: 'HTML-XSS',
          severity: check.severity,
          category: 'xss' as SecurityCategory,
          owaspCategory: 'A03:2021-Injection' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description,
          remediation: 'Use textContent instead of innerHTML, sanitize user input, and avoid inline event handlers.',
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'medium' as ConfidenceLevel
        });
      }
    }

    // Check for insecure content loading
    const insecurePatterns = [
      {
        pattern: /src\s*=\s*["']http:\/\//gi,
        message: 'Insecure HTTP resource loaded',
        severity: 'medium' as SeverityLevel
      },
      {
        pattern: /href\s*=\s*["']http:\/\//gi,
        message: 'Insecure HTTP link',
        severity: 'low' as SeverityLevel
      }
    ];

    for (const check of insecurePatterns) {
      const regex = new RegExp(check.pattern.source, 'gi');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `html-insecure-${match.index}`,
          ruleId: 'HTML-INSECURE',
          severity: check.severity,
          category: 'insecure-configuration' as SecurityCategory,
          owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: 'Loading resources over HTTP instead of HTTPS can expose users to MITM attacks.',
          remediation: 'Use HTTPS for all external resources.',
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    }

    return findings;
  }

  private scanMarkdown(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check for suspicious markdown content
    const suspiciousPatterns = [
      {
        pattern: /!\[.*?\]\(javascript:/gi,
        message: 'JavaScript protocol in image source',
        severity: 'high' as SeverityLevel
      },
      {
        pattern: /\[.*?\]\(javascript:/gi,
        message: 'JavaScript protocol in link',
        severity: 'high' as SeverityLevel
      },
      {
        pattern: /```\s*\n.*?eval\s*\(/gis,
        message: 'Eval usage in code block',
        severity: 'medium' as SeverityLevel
      }
    ];

    for (const check of suspiciousPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `md-suspicious-${match.index}`,
          ruleId: 'MD-SUSPICIOUS',
          severity: check.severity,
          category: 'xss' as SecurityCategory,
          owaspCategory: 'A03:2021-Injection' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: 'Potentially dangerous content detected in markdown.',
          remediation: 'Review and sanitize markdown content before rendering.',
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'low' as ConfidenceLevel
        });
      }
    }

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
          id: `markup-secret-${secretPattern.name}-${match.index}`,
          ruleId: 'MARKUP-SECRET',
          severity: secretPattern.severity,
          category: 'hardcoded-secrets' as SecurityCategory,
          owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: secretPattern.description,
          description: `Potential ${secretPattern.name} detected in markup file.`,
          remediation: 'Remove hardcoded secrets and use secure secret management.',
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
      .replace(/key["']?\s*[:=]\s*["'][^"']{16,}["']/gi, 'key: "***MASKED***"');
  }
}
