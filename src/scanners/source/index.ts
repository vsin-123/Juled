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
import { ALL_OWASP_RULES } from '../../rules/owasp/top10-rules';

export class SourceCodeScanner {
  private name = 'Source Code Scanner';
  private version = '1.0.0';

  public async scan(filePath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: SecurityFinding[] = [];

    const extension = path.extname(filePath).toLowerCase();
    const language = this.detectLanguage(extension, path.basename(filePath));

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      // Language-specific security checks
      findings.push(...this.scanLanguageSpecific(content, lines, filePath, language));

      // Generic security checks for all languages
      findings.push(...this.scanGenericSecurity(content, lines, filePath, language));

      // Secret detection
      findings.push(...this.detectSecrets(content, lines, filePath));

      // OWASP rules
      findings.push(...this.checkOWASPRules(content, lines, filePath, language));

    } catch (error) {
      findings.push({
        id: `source-error-${Date.now()}`,
        ruleId: 'SOURCE-ERROR',
        severity: 'info' as SeverityLevel,
        category: 'input-validation' as SecurityCategory,
        filePath,
        lineNumber: 0,
        message: `Error scanning file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        description: 'An error occurred while scanning the source code file',
        confidence: 'low' as ConfidenceLevel
      });
    }

    return {
      filePath,
      fileType: language,
      findings,
      scanDuration: Date.now() - startTime,
      scannedAt: new Date(),
      scannerVersion: this.version
    };
  }

  private detectLanguage(ext: string, basename: string): string {
    const languageMap: Record<string, string> = {
      '.js': 'javascript',
      '.jsx': 'javascript',
      '.mjs': 'javascript',
      '.cjs': 'javascript',
      '.ts': 'typescript',
      '.tsx': 'typescript',
      '.py': 'python',
      '.pyw': 'python',
      '.pyi': 'python',
      '.java': 'java',
      '.go': 'go',
      '.rb': 'ruby',
      '.rbw': 'ruby',
      '.rake': 'ruby',
      '.gemspec': 'ruby',
      '.php': 'php',
      '.phtml': 'php',
      '.php3': 'php',
      '.php4': 'php',
      '.php5': 'php',
      '.cs': 'csharp',
      '.csx': 'csharp',
      '.cpp': 'cpp',
      '.cxx': 'cpp',
      '.cc': 'cpp',
      '.c': 'c',
      '.h': 'c',
      '.hpp': 'cpp',
      '.rs': 'rust',
      '.swift': 'swift',
      '.kt': 'kotlin',
      '.kts': 'kotlin',
      '.scala': 'scala',
      '.sc': 'scala',
      '.sh': 'shell',
      '.bash': 'shell',
      '.zsh': 'shell',
      '.ksh': 'shell',
      '.ps1': 'powershell',
      '.psm1': 'powershell',
      '.psd1': 'powershell',
      '.pl': 'perl',
      '.pm': 'perl',
      '.lua': 'lua',
      '.r': 'r',
      '.R': 'r',
      '.m': 'matlab',
      '.mlx': 'matlab'
    };

    return languageMap[ext] || 'unknown';
  }

  private scanLanguageSpecific(
    content: string,
    lines: string[],
    filePath: string,
    language: string
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    switch (language) {
      case 'javascript':
      case 'typescript':
        findings.push(...this.scanJavaScript(content, lines, filePath));
        break;
      case 'python':
        findings.push(...this.scanPython(content, lines, filePath));
        break;
      case 'java':
        findings.push(...this.scanJava(content, lines, filePath));
        break;
      case 'php':
        findings.push(...this.scanPHP(content, lines, filePath));
        break;
      case 'ruby':
        findings.push(...this.scanRuby(content, lines, filePath));
        break;
      case 'go':
        findings.push(...this.scanGo(content, lines, filePath));
        break;
      case 'csharp':
        findings.push(...this.scanCSharp(content, lines, filePath));
        break;
      case 'cpp':
      case 'c':
        findings.push(...this.scanC(content, lines, filePath));
        break;
      case 'shell':
        findings.push(...this.scanShell(content, lines, filePath));
        break;
    }

    return findings;
  }

  private scanJavaScript(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Dangerous patterns in JavaScript/TypeScript
    const dangerousPatterns: Array<{ pattern: RegExp; message: string; severity: SeverityLevel; category: SecurityCategory; description?: string; }> = [
      {
        pattern: /eval\s*\(/g,
        message: 'Dangerous eval() usage detected',
        severity: 'high' as SeverityLevel,
        category: 'command-injection' as SecurityCategory,
        description: 'eval() can execute arbitrary code and is dangerous with user input'
      },
      {
        pattern: /new\s+Function\s*\(/g,
        message: 'Function constructor usage detected',
        severity: 'high' as SeverityLevel,
        category: 'command-injection' as SecurityCategory,
        description: 'Function constructor is similar to eval() and can execute arbitrary code'
      },
      {
        pattern: /setTimeout\s*\(\s*["'][^"']+["']/g,
        message: 'setTimeout with string argument',
        severity: 'medium' as SeverityLevel,
        category: 'command-injection' as SecurityCategory,
        description: 'setTimeout with string argument uses eval-like behavior'
      },
      {
        pattern: /setInterval\s*\(\s*["'][^"']+["']/g,
        message: 'setInterval with string argument',
        severity: 'medium' as SeverityLevel,
        category: 'command-injection' as SecurityCategory,
        description: 'setInterval with string argument uses eval-like behavior'
      },
      {
        pattern: /innerHTML\s*=\s*[^;]+/g,
        message: 'innerHTML assignment detected',
        severity: 'medium' as SeverityLevel,
        category: 'xss' as SecurityCategory,
        description: 'innerHTML can lead to XSS if user input is not properly sanitized'
      },
      {
        pattern: /document\.write\s*\(/g,
        message: 'document.write usage detected',
        severity: 'medium' as SeverityLevel,
        category: 'xss' as SecurityCategory,
        description: 'document.write can lead to XSS vulnerabilities'
      },
      {
        pattern: /\.exec\s*\(\s*.*\+\s*/g,
        message: 'Potential command injection in exec()',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory,
        description: 'String concatenation in exec() can lead to command injection'
      },
      {
        pattern: /child_process.*exec.*\+/g,
        message: 'Potential command injection',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory,
        description: 'String concatenation in child_process can lead to command injection'
      },
      {
        pattern: /Math\.random\s*\(\s*\)/g,
        message: 'Insecure randomness',
        severity: 'medium' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory,
        description: 'Math.random() is not cryptographically secure'
      },
      {
        pattern: /md5\s*\(/gi,
        message: 'Weak hashing algorithm (MD5)',
        severity: 'high' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory,
        description: 'MD5 is cryptographically broken and should not be used'
      },
      {
        pattern: /sha1\s*\(/gi,
        message: 'Weak hashing algorithm (SHA1)',
        severity: 'high' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory,
        description: 'SHA1 is cryptographically broken and should not be used'
      },
      {
        pattern: /localStorage\.setItem\s*\(\s*["']password/gi,
        message: 'Sensitive data in localStorage',
        severity: 'high' as SeverityLevel,
        category: 'insecure-configuration' as SecurityCategory,
        description: 'Storing sensitive data in localStorage is insecure'
      }
    ];

    for (const check of dangerousPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `js-${check.category}-${match.index}`,
          ruleId: `JS-${check.category.toUpperCase()}`,
          severity: check.severity,
          category: check.category,
          owaspCategory: this.mapToOWASP(check.category),
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description || `${check.message} detected in JavaScript code`,
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    }

    return findings;
  }

  private scanPython(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const dangerousPatterns: Array<{
      pattern: RegExp;
      message: string;
      severity: SeverityLevel;
      category: SecurityCategory;
      description?: string;
    }> = [
      {
        pattern: /eval\s*\(/g,
        message: 'Dangerous eval() usage',
        severity: 'high',
        category: 'command-injection',
        description: 'eval() can execute arbitrary code and is dangerous with user input'
      },
      {
        pattern: /exec\s*\(/g,
        message: 'Dangerous exec() usage',
        severity: 'high',
        category: 'command-injection',
        description: 'exec() can execute arbitrary code and is dangerous with user input'
      },
      {
        pattern: /pickle\.loads?\s*\(/g,
        message: 'Insecure deserialization with pickle',
        severity: 'critical',
        category: 'input-validation',
        description: 'pickle can execute arbitrary code during deserialization'
      },
      {
        pattern: /yaml\.load\s*\(/g,
        message: 'Unsafe YAML loading',
        severity: 'critical',
        category: 'input-validation',
        description: 'yaml.load() can execute arbitrary code. Use yaml.safe_load() instead'
      },
      {
        pattern: /subprocess\.call\s*\(\s*[^,]*shell\s*=\s*True/g,
        message: 'Subprocess with shell=True',
        severity: 'high',
        category: 'command-injection',
        description: 'shell=True can lead to command injection with user input'
      },
      {
        pattern: /os\.system\s*\(/g,
        message: 'os.system() usage',
        severity: 'medium',
        category: 'command-injection',
        description: 'os.system() passes command to system shell which can be dangerous'
      },
      {
        pattern: /input\s*\(\s*\)/g,
        message: 'Python 2 input() used',
        severity: 'high',
        category: 'input-validation',
        description: 'input() in Python 2 evaluates the input as code (use raw_input instead)'
      },
      {
        pattern: /hashlib\.md5\s*\(/g,
        message: 'Weak hashing (MD5)',
        severity: 'high',
        category: 'weak-cryptography',
        description: 'MD5 is cryptographically broken and should not be used'
      },
      {
        pattern: /hashlib\.sha1\s*\(/g,
        message: 'Weak hashing (SHA1)',
        severity: 'high',
        category: 'weak-cryptography',
        description: 'SHA1 is cryptographically broken and should not be used'
      },
      {
        pattern: /random\.random\s*\(\s*\)/g,
        message: 'Insecure randomness',
        severity: 'medium',
        category: 'weak-cryptography',
        description: 'random is not cryptographically secure. Use secrets module instead'
      },
      {
        pattern: /DEBUG\s*=\s*True/g,
        message: 'Debug mode enabled',
        severity: 'medium',
        category: 'insecure-configuration',
        description: 'Debug mode should not be enabled in production'
      },
      {
        pattern: /verify\s*=\s*False/g,
        message: 'SSL verification disabled',
        severity: 'high',
        category: 'weak-cryptography',
        description: 'Disabling SSL verification exposes to MITM attacks'
      }
    ];

    for (const check of dangerousPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `py-${check.category}-${match.index}`,
          ruleId: `PY-${check.category.toUpperCase()}`,
          severity: check.severity,
          category: check.category,
          owaspCategory: this.mapToOWASP(check.category),
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description || `${check.message} detected in Python code`,
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    }

    return findings;
  }

  private scanJava(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const dangerousPatterns: Array<{
      pattern: RegExp;
      message: string;
      severity: SeverityLevel;
      category: SecurityCategory;
      description?: string;
    }> = [
      {
        pattern: /Runtime\.getRuntime\(\)\.exec\s*\(/g,
        message: 'Command execution via Runtime.exec()',
        severity: 'medium',
        category: 'command-injection',
        description: 'Runtime.exec() can be dangerous with user input'
      },
      {
        pattern: /ProcessBuilder\s*\(/g,
        message: 'ProcessBuilder usage',
        severity: 'medium',
        category: 'command-injection',
        description: 'ProcessBuilder can be dangerous with user input'
      },
      {
        pattern: /ObjectInputStream.*readObject\s*\(/g,
        message: 'Insecure deserialization',
        severity: 'critical',
        category: 'input-validation',
        description: 'Java deserialization can execute arbitrary code'
      },
      {
        pattern: /MessageDigest\.getInstance\s*\(\s*["']MD5["']/g,
        message: 'Weak hashing (MD5)',
        severity: 'high',
        category: 'weak-cryptography',
        description: 'MD5 is cryptographically broken and should not be used'
      },
      {
        pattern: /MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']/g,
        message: 'Weak hashing (SHA1)',
        severity: 'high',
        category: 'weak-cryptography',
        description: 'SHA1 is cryptographically broken and should not be used'
      },
      {
        pattern: /Random\s*\(\s*\)/g,
        message: 'Insecure randomness',
        severity: 'medium',
        category: 'weak-cryptography',
        description: 'Random is not cryptographically secure. Use SecureRandom instead'
      },
      {
        pattern: /response\.sendRedirect\s*\(\s*.*\+\s*/g,
        message: 'Potential open redirect',
        severity: 'medium',
        category: 'input-validation',
        description: 'User-controlled redirect can lead to phishing attacks'
      },
      {
        pattern: /@RequestMapping.*method\s*=\s*RequestMethod\.GET[^}]*@RequestBody/s,
        message: 'GET method with RequestBody',
        severity: 'low',
        category: 'insecure-configuration',
        description: 'GET requests should not have request bodies'
      }
    ];

    for (const check of dangerousPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `java-${check.category}-${match.index}`,
          ruleId: `JAVA-${check.category.toUpperCase()}`,
          severity: check.severity,
          category: check.category,
          owaspCategory: this.mapToOWASP(check.category),
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description || `${check.message} detected in Java code`,
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    }

    return findings;
  }

  private scanPHP(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const dangerousPatterns: Array<{ pattern: RegExp; message: string; severity: SeverityLevel; category: SecurityCategory; description?: string; }> = [
      {
        pattern: /eval\s*\(\s*\$/g,
        message: 'Dangerous eval() with variable',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /exec\s*\(\s*\$/g,
        message: 'Command execution with user input',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /system\s*\(\s*\$/g,
        message: 'System command with user input',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /passthru\s*\(\s*\$/g,
        message: 'Passthru with user input',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /shell_exec\s*\(\s*\$/g,
        message: 'Shell execution with user input',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /mysql_query\s*\(\s*\$/g,
        message: 'SQL query with user input',
        severity: 'critical' as SeverityLevel,
        category: 'sql-injection' as SecurityCategory
      },
      {
        pattern: /mysqli_query\s*\(\s*.*\$/g,
        message: 'Potential SQL injection',
        severity: 'high' as SeverityLevel,
        category: 'sql-injection' as SecurityCategory
      },
      {
        pattern: /unserialize\s*\(\s*\$_/g,
        message: 'Insecure deserialization',
        severity: 'critical' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      },
      {
        pattern: /md5\s*\(/g,
        message: 'Weak hashing (MD5)',
        severity: 'high' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory
      },
      {
        pattern: /include\s*\(\s*\$_/g,
        message: 'File inclusion with user input',
        severity: 'critical' as SeverityLevel,
        category: 'path-traversal' as SecurityCategory
      },
      {
        pattern: /require\s*\(\s*\$_/g,
        message: 'File require with user input',
        severity: 'critical' as SeverityLevel,
        category: 'path-traversal' as SecurityCategory
      }
    ];

    for (const check of dangerousPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `php-${check.category}-${match.index}`,
          ruleId: `PHP-${check.category.toUpperCase()}`,
          severity: check.severity,
          category: check.category,
          owaspCategory: this.mapToOWASP(check.category),
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description || `${check.message} detected in PHP code`,
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    }

    return findings;
  }

  private scanRuby(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const dangerousPatterns: Array<{ pattern: RegExp; message: string; severity: SeverityLevel; category: SecurityCategory; description?: string; }> = [
      {
        pattern: /eval\s*\(/g,
        message: 'Dangerous eval() usage',
        severity: 'high' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /Kernel\.eval\s*\(/g,
        message: 'Dangerous Kernel.eval() usage',
        severity: 'high' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /Marshal\.load\s*\(/g,
        message: 'Insecure deserialization',
        severity: 'critical' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      },
      {
        pattern: /YAML\.load\s*\(/g,
        message: 'Unsafe YAML loading',
        severity: 'critical' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      },
      {
        pattern: /system\s*\(\s*.*#/g,
        message: 'Command execution with interpolation',
        severity: 'high' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /`[^`]*#/g,
        message: 'Backtick command with interpolation',
        severity: 'high' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /exec\s*\(\s*.*#/g,
        message: 'Exec with interpolation',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /MD5\.new/g,
        message: 'Weak hashing (MD5)',
        severity: 'high' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory
      },
      {
        pattern: /OpenSSL::Digest::MD5/g,
        message: 'Weak hashing (MD5)',
        severity: 'high' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory
      }
    ];

    for (const check of dangerousPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `ruby-${check.category}-${match.index}`,
          ruleId: `RUBY-${check.category.toUpperCase()}`,
          severity: check.severity,
          category: check.category,
          owaspCategory: this.mapToOWASP(check.category),
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description || `${check.message} detected in Ruby code`,
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    }

    return findings;
  }

  private scanGo(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const dangerousPatterns: Array<{ pattern: RegExp; message: string; severity: SeverityLevel; category: SecurityCategory; description?: string; }> = [
      {
        pattern: /exec\.Command\s*\(\s*["'][^"']*["']\s*,\s*.*\+\s*/g,
        message: 'Potential command injection',
        severity: 'high' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /exec\.CommandContext\s*\(\s*.*\+\s*/g,
        message: 'Potential command injection',
        severity: 'high' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /math\/rand/g,
        message: 'Insecure randomness',
        severity: 'medium' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory
      },
      {
        pattern: /InsecureSkipVerify\s*:\s*true/g,
        message: 'SSL verification disabled',
        severity: 'high' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory
      }
    ];

    for (const check of dangerousPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `go-${check.category}-${match.index}`,
          ruleId: `GO-${check.category.toUpperCase()}`,
          severity: check.severity,
          category: check.category,
          owaspCategory: this.mapToOWASP(check.category),
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description || `${check.message} detected in Go code`,
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    }

    return findings;
  }

  private scanCSharp(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const dangerousPatterns: Array<{ pattern: RegExp; message: string; severity: SeverityLevel; category: SecurityCategory; description?: string; }> = [
      {
        pattern: /Process\.Start\s*\(/g,
        message: 'Process execution',
        severity: 'medium' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /BinaryFormatter\s*\(/g,
        message: 'Insecure deserialization (BinaryFormatter)',
        severity: 'critical' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      },
      {
        pattern: /JavaScriptSerializer\s*\(/g,
        message: 'Insecure deserialization (JavaScriptSerializer)',
        severity: 'critical' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      },
      {
        pattern: /MD5\.Create\s*\(\s*\)/g,
        message: 'Weak hashing (MD5)',
        severity: 'high' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory
      },
      {
        pattern: /SHA1\.Create\s*\(\s*\)/g,
        message: 'Weak hashing (SHA1)',
        severity: 'high' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory
      },
      {
        pattern: /Random\s*\(\s*\)/g,
        message: 'Insecure randomness',
        severity: 'medium' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory
      },
      {
        pattern: /Request\.QueryString\[.*\].*Response\.Write/g,
        message: 'Potential XSS',
        severity: 'high' as SeverityLevel,
        category: 'xss' as SecurityCategory
      }
    ];

    for (const check of dangerousPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `csharp-${check.category}-${match.index}`,
          ruleId: `CS-${check.category.toUpperCase()}`,
          severity: check.severity,
          category: check.category,
          owaspCategory: this.mapToOWASP(check.category),
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description || `${check.message} detected in C# code`,
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    }

    return findings;
  }

  private scanC(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const dangerousPatterns: Array<{ pattern: RegExp; message: string; severity: SeverityLevel; category: SecurityCategory; description?: string; }> = [
      {
        pattern: /strcpy\s*\(/g,
        message: 'Unsafe string copy (strcpy)',
        severity: 'high' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      },
      {
        pattern: /strcat\s*\(/g,
        message: 'Unsafe string concatenation (strcat)',
        severity: 'high' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      },
      {
        pattern: /sprintf\s*\(/g,
        message: 'Unsafe string formatting (sprintf)',
        severity: 'high' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      },
      {
        pattern: /gets\s*\(/g,
        message: 'Dangerous gets() function',
        severity: 'critical' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      },
      {
        pattern: /scanf\s*\([^,]*\)/g,
        message: 'Unsafe scanf usage',
        severity: 'medium' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      },
      {
        pattern: /system\s*\(/g,
        message: 'Command execution',
        severity: 'high' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /rand\s*\(\s*\)/g,
        message: 'Insecure randomness',
        severity: 'medium' as SeverityLevel,
        category: 'weak-cryptography' as SecurityCategory
      },
      {
        pattern: /memcpy\s*\(/g,
        message: 'Potential buffer overflow (memcpy)',
        severity: 'medium' as SeverityLevel,
        category: 'input-validation' as SecurityCategory
      }
    ];

    for (const check of dangerousPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `c-${check.category}-${match.index}`,
          ruleId: `C-${check.category.toUpperCase()}`,
          severity: check.severity,
          category: check.category,
          owaspCategory: this.mapToOWASP(check.category),
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description || `${check.message} detected in C/C++ code`,
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    }

    return findings;
  }

  private scanShell(content: string, lines: string[], filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    const dangerousPatterns: Array<{ pattern: RegExp; message: string; severity: SeverityLevel; category: SecurityCategory; description?: string; }> = [
      {
        pattern: /eval\s+\$/g,
        message: 'Dangerous eval usage',
        severity: 'high' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /eval\s+"[^"]*\$/g,
        message: 'Eval with variable',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /`[^`]*\$/g,
        message: 'Command substitution with variable',
        severity: 'medium' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /\$\([^)]*\$/g,
        message: 'Command substitution with variable',
        severity: 'medium' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /chmod\s+777/g,
        message: 'Overly permissive file permissions (777)',
        severity: 'medium' as SeverityLevel,
        category: 'file-permissions' as SecurityCategory
      },
      {
        pattern: /chmod\s+\+s/g,
        message: 'Setuid/setgid bit set',
        severity: 'medium' as SeverityLevel,
        category: 'file-permissions' as SecurityCategory
      },
      {
        pattern: /curl.*\|.*sh/g,
        message: 'Piping curl to shell',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /wget.*-.*\|.*sh/g,
        message: 'Piping wget to shell',
        severity: 'critical' as SeverityLevel,
        category: 'command-injection' as SecurityCategory
      },
      {
        pattern: /password\s*=\s*["'][^"']+["']/gi,
        message: 'Hardcoded password',
        severity: 'critical' as SeverityLevel,
        category: 'hardcoded-secrets' as SecurityCategory
      }
    ];

    for (const check of dangerousPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        findings.push({
          id: `sh-${check.category}-${match.index}`,
          ruleId: `SH-${check.category.toUpperCase()}`,
          severity: check.severity,
          category: check.category,
          owaspCategory: this.mapToOWASP(check.category),
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: check.description || `${check.message} detected in shell script`,
          codeSnippet: codeSnippet.length > 200 ? codeSnippet.substring(0, 200) + '...' : codeSnippet,
          confidence: 'high' as ConfidenceLevel
        });
      }
    }

    return findings;
  }

  private scanGenericSecurity(
    content: string,
    lines: string[],
    filePath: string,
    language: string
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Hardcoded credentials patterns (generic across languages)
    const credentialPatterns = [
      {
        pattern: /password\s*=\s*["'][^"']{4,}["']/gi,
        message: 'Hardcoded password',
        severity: 'critical' as SeverityLevel
      },
      {
        pattern: /passwd\s*=\s*["'][^"']{4,}["']/gi,
        message: 'Hardcoded password',
        severity: 'critical' as SeverityLevel
      },
      {
        pattern: /pwd\s*=\s*["'][^"']{4,}["']/gi,
        message: 'Hardcoded password',
        severity: 'critical' as SeverityLevel
      },
      {
        pattern: /secret\s*=\s*["'][^"']{8,}["']/gi,
        message: 'Hardcoded secret',
        severity: 'critical' as SeverityLevel
      },
      {
        pattern: /api[_-]?key\s*=\s*["'][^"']{8,}["']/gi,
        message: 'Hardcoded API key',
        severity: 'critical' as SeverityLevel
      },
      {
        pattern: /token\s*=\s*["'][^"']{8,}["']/gi,
        message: 'Hardcoded token',
        severity: 'critical' as SeverityLevel
      },
      {
        pattern: /private[_-]?key\s*=\s*["'][^"']{8,}["']/gi,
        message: 'Hardcoded private key',
        severity: 'critical' as SeverityLevel
      }
    ];

    for (const check of credentialPatterns) {
      const regex = new RegExp(check.pattern.source, check.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const codeSnippet = lines[lineNumber - 1]?.trim() || '';

        // Skip if it looks like a placeholder
        if (this.isPlaceholder(codeSnippet)) {
          continue;
        }

        findings.push({
          id: `source-cred-${match.index}`,
          ruleId: 'SOURCE-HARDCODED-CREDENTIALS',
          severity: check.severity,
          category: 'hardcoded-secrets' as SecurityCategory,
          owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: check.message,
          description: `Hardcoded credentials detected in ${language} code. Never store credentials in source code.`,
          remediation: 'Use environment variables, configuration files, or secret management tools.',
          codeSnippet: this.maskSensitiveData(codeSnippet),
          confidence: 'high' as ConfidenceLevel
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
          id: `source-secret-${secretPattern.name}-${match.index}`,
          ruleId: 'SOURCE-SECRET',
          severity: secretPattern.severity,
          category: 'hardcoded-secrets' as SecurityCategory,
          owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
          filePath,
          lineNumber,
          columnNumber: match.index - this.getLineStartIndex(content, lineNumber) + 1,
          message: secretPattern.description,
          description: `Potential ${secretPattern.name} detected in source code.`,
          remediation: 'Remove hardcoded secrets and use secure secret management.',
          codeSnippet: this.maskSensitiveData(codeSnippet),
          confidence: 'medium' as ConfidenceLevel
        });
      }
    });

    return findings;
  }

  private checkOWASPRules(
    content: string,
    lines: string[],
    filePath: string,
    language: string
  ): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Filter rules relevant to source code
    const sourceRules = ALL_OWASP_RULES.filter(rule =>
      rule.fileTypes.includes('javascript') ||
      rule.fileTypes.includes('python') ||
      rule.fileTypes.includes('java') ||
      rule.fileTypes.includes('php') ||
      rule.fileTypes.includes('ruby') ||
      rule.fileTypes.includes('go') ||
      rule.fileTypes.includes('csharp')
    );

    for (const rule of sourceRules) {
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

  private mapToOWASP(category: SecurityCategory): OwaspCategory {
    const mapping: Record<string, OwaspCategory> = {
      'sql-injection': 'A03:2021-Injection' as OwaspCategory,
      'command-injection': 'A03:2021-Injection' as OwaspCategory,
      'xss': 'A03:2021-Injection' as OwaspCategory,
      'path-traversal': 'A01:2021-Broken Access Control' as OwaspCategory,
      'hardcoded-secrets': 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
      'insecure-configuration': 'A05:2021-Security Misconfiguration' as OwaspCategory,
      'weak-cryptography': 'A02:2021-Cryptographic Failures' as OwaspCategory,
      'input-validation': 'A03:2021-Injection' as OwaspCategory,
      'file-permissions': 'A05:2021-Security Misconfiguration' as OwaspCategory
    };

    return mapping[category] || 'A05:2021-Security Misconfiguration' as OwaspCategory;
  }

  private isPlaceholder(line: string): boolean {
    const placeholderPatterns = [
      /process\.env\./i,
      /process\.env\[/i,
      /os\.environ/i,
      /System\.getenv/i,
      /getenv\s*\(/i,
      /config\.get/i,
      /settings\./i,
      /options\./i,
      /cfg\./i,
      /\$\{/,
      /\$\w+/,
      /YOUR_/i,
      /CHANGE_/i,
      /PLACEHOLDER/i,
      /XXX+/i,
      /TODO/i,
      /FIXME/i
    ];

    return placeholderPatterns.some(pattern => pattern.test(line));
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
