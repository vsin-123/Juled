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
import { TERRAFORM_SECURITY_RULES } from '../../rules/infrastructure/terraform-rules';
import { DOCKERFILE_SECURITY_RULES, DOCKER_COMPOSE_SECURITY_RULES } from '../../rules/infrastructure/docker-rules';
import { KUBERNETES_SECURITY_RULES } from '../../rules/infrastructure/kubernetes-rules';
import { SECRET_PATTERNS } from '../../rules/secrets/patterns';

export class InfrastructureScanner {
  private name = 'Infrastructure Scanner';
  private version = '1.0.0';

  public async scan(filePath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];

    const extension = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath).toLowerCase();

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      // Determine file type and apply appropriate rules
      if (this.isTerraform(extension, basename)) {
        findings.push(...this.scanTerraform(content, lines, filePath));
      } else if (this.isDockerfile(extension, basename)) {
        findings.push(...this.scanDockerfile(content, lines, filePath));
      } else if (this.isDockerCompose(basename)) {
        findings.push(...this.scanDockerCompose(content, lines, filePath));
      } else if (this.isKubernetes(extension, basename, content)) {
        findings.push(...this.scanKubernetes(content, lines, filePath));
      } else {
        // Generic infrastructure scan
        findings.push(...this.scanGeneric(content, lines, filePath));
      }

      // Always check for secrets
      findings.push(...this.detectSecrets(content, lines, filePath));

    } catch (error) {
      findings.push({
        id: `infra-error-${Date.now()}`,
        ruleId: 'INFRA-ERROR',
        severity: 'info' as SeverityLevel,
        category: 'infrastructure' as SecurityCategory,
        filePath,
        lineNumber: 0,
        message: `Error scanning file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        description: 'An error occurred while scanning the infrastructure file',
        confidence: 'low' as ConfidenceLevel
      });
    }

    return {
      filePath,
      fileType: this.detectFileType(extension, basename),
      findings,
      scanDuration: Date.now() - startTime,
      scannedAt: new Date(),
      scannerVersion: this.version
    };
  }

  private isTerraform(ext: string, basename: string): boolean {
    return ext === '.tf' || ext === '.tfvars' || ext === '.hcl' ||
           ['main.tf', 'variables.tf', 'outputs.tf', 'terraform.tfvars'].includes(basename);
  }

  private isDockerfile(ext: string, basename: string): boolean {
    return ext === '.dockerfile' || basename === 'dockerfile' || basename.startsWith('dockerfile.');
  }

  private isDockerCompose(basename: string): boolean {
    return ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'].includes(basename);
  }

  private isKubernetes(ext: string, basename: string, content: string): boolean {
    return ext === '.yml' || ext === '.yaml' &&
           (content.includes('apiVersion:') ||
            content.includes('kind:') ||
            basename.includes('deployment') ||
            basename.includes('service') ||
            basename.includes('configmap') ||
            basename.includes('secret') ||
            basename.includes('ingress') ||
            basename.includes('pod'));
  }

  private detectFileType(ext: string, basename: string): string {
    if (this.isTerraform(ext, basename)) return 'terraform';
    if (this.isDockerfile(ext, basename)) return 'dockerfile';
    if (this.isDockerCompose(basename)) return 'docker-compose';
    if (ext === '.yml' || ext === '.yaml') return 'kubernetes';
    return 'infrastructure';
  }

  private scanTerraform(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const rule of TERRAFORM_SECURITY_RULES) {
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

  private scanDockerfile(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const rule of DOCKERFILE_SECURITY_RULES) {
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

  private scanDockerCompose(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const rule of DOCKER_COMPOSE_SECURITY_RULES) {
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

  private scanKubernetes(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const rule of KUBERNETES_SECURITY_RULES) {
      for (const pattern of rule.patterns) {
        const regex = new RegExp(pattern.source, 'gi');
        let match: RegExpExecArray | null;

        while ((match = regex.exec(content)) !== null) {
          const lineNumber = this.getLineNumber(content, match.index);
          const codeSnippet = lines[lineNumber - 1]?.trim() || '';

          // Check negative patterns
          if (rule.negativePatterns) {
            const hasNegativePattern = rule.negativePatterns.some(negPattern =>
              negPattern.test(content.substring(match!.index - 200, match!.index + 200))
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

  private scanGeneric(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Generic infrastructure security checks
    const genericPatterns = [
      {
        pattern: /0\.0\.0\.0\/0/g,
        severity: 'high' as SeverityLevel,
        message: 'Unrestricted access from 0.0.0.0/0 detected',
        description: 'Resource allows access from any IP address.',
        remediation: 'Restrict access to specific IP ranges.',
        category: 'infrastructure' as SecurityCategory
      },
      {
        pattern: /password\s*=\s*["'][^"']{4,}["']/gi,
        severity: 'critical' as SeverityLevel,
        message: 'Hardcoded password detected',
        description: 'Password is hardcoded in infrastructure configuration.',
        remediation: 'Use variables, secrets management, or environment variables.',
        category: 'hardcoded-secrets' as SecurityCategory
      },
      {
        pattern: /admin|root|administrator/i,
        severity: 'medium' as SeverityLevel,
        message: 'Default admin user detected',
        description: 'Default administrative username may be in use.',
        remediation: 'Use non-default usernames for admin accounts.',
        category: 'authentication' as SecurityCategory
      }
    ];

    for (const check of genericPatterns) {
      const regex = new RegExp(check.pattern.source, 'gi');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `infra-generic-${match.index}`,
          ruleId: 'INFRA-GENERIC',
          severity: check.severity,
          category: check.category,
          owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description,
          remediation: check.remediation,
          codeSnippet: this.maskSensitiveData(codeSnippet),
          confidence: 'medium' as ConfidenceLevel
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
          id: `infra-secret-${secretPattern.name}-${match.index}`,
          ruleId: 'INFRA-SECRET',
          severity: secretPattern.severity,
          category: 'hardcoded-secrets' as SecurityCategory,
          owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: secretPattern.description,
          description: `Potential ${secretPattern.name} detected in infrastructure code.`,
          remediation: 'Remove hardcoded secrets and use secure secret management tools like HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secrets.',
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
