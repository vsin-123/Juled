import { SQLInjectionPattern, SecurityRule, SecurityCategory, OwaspCategory } from '../../types';

export const SQL_INJECTION_PATTERNS: SQLInjectionPattern[] = [
  {
    pattern: /(\$\{|\{|\%\{|\#\{)\s*\w+.*?\}/,
    dialect: ['generic'],
    context: ['template', 'interpolation'],
    severity: 'high'
  },
  {
    pattern: /SELECT\s+.*\s+FROM\s+.*\+\s*\w+/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['concatenation'],
    severity: 'critical'
  },
  {
    pattern: /INSERT\s+INTO\s+.*\+\s*\w+/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['concatenation'],
    severity: 'critical'
  },
  {
    pattern: /UPDATE\s+.*\s+SET\s+.*\+\s*\w+/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['concatenation'],
    severity: 'critical'
  },
  {
    pattern: /DELETE\s+FROM\s+.*\+\s*\w+/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['concatenation'],
    severity: 'critical'
  },
  {
    pattern: /WHERE\s+.*=\s*["\']?\s*\$\w+/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['variable-interpolation'],
    severity: 'critical'
  },
  {
    pattern: /WHERE\s+.*=\s*["\']?\s*\{.*\}/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['template-literal'],
    severity: 'critical'
  },
  {
    pattern: /exec\s*\(\s*["\'].*\$\w+/i,
    dialect: ['mssql'],
    context: ['stored-procedure'],
    severity: 'critical'
  },
  {
    pattern: /execute\s+immediate\s+.*\|\|/i,
    dialect: ['oracle', 'postgresql'],
    context: ['dynamic-sql'],
    severity: 'critical'
  },
  {
    pattern: /sp_executesql\s+.*\$/i,
    dialect: ['mssql'],
    context: ['dynamic-sql'],
    severity: 'high'
  },
  {
    pattern: /UNION\s+SELECT/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['union-based'],
    severity: 'high'
  },
  {
    pattern: /UNION\s+ALL\s+SELECT/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['union-based'],
    severity: 'high'
  },
  {
    pattern: /OR\s+['"]\d+['"]\s*=\s*['"]\d+['"]/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['boolean-based'],
    severity: 'high'
  },
  {
    pattern: /AND\s+['"]\d+['"]\s*=\s*['"]\d+['"]/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['boolean-based'],
    severity: 'medium'
  },
  {
    pattern: /SLEEP\s*\(\s*\d+\s*\)/i,
    dialect: ['mysql', 'postgresql'],
    context: ['time-based'],
    severity: 'high'
  },
  {
    pattern: /WAITFOR\s+DELAY/i,
    dialect: ['mssql'],
    context: ['time-based'],
    severity: 'high'
  },
  {
    pattern: /pg_sleep\s*\(/i,
    dialect: ['postgresql'],
    context: ['time-based'],
    severity: 'high'
  },
  {
    pattern: /benchmark\s*\(/i,
    dialect: ['mysql'],
    context: ['time-based'],
    severity: 'high'
  },
  {
    pattern: /LOAD_FILE\s*\(/i,
    dialect: ['mysql'],
    context: ['file-access'],
    severity: 'critical'
  },
  {
    pattern: /INTO\s+OUTFILE/i,
    dialect: ['mysql'],
    context: ['file-write'],
    severity: 'critical'
  },
  {
    pattern: /xp_cmdshell/i,
    dialect: ['mssql'],
    context: ['command-execution'],
    severity: 'critical'
  },
  {
    pattern: /xp_regread/i,
    dialect: ['mssql'],
    context: ['registry-access'],
    severity: 'high'
  },
  {
    pattern: /xp_regwrite/i,
    dialect: ['mssql'],
    context: ['registry-write'],
    severity: 'critical'
  },
  {
    pattern: /UTL_HTTP\./i,
    dialect: ['oracle'],
    context: ['network-access'],
    severity: 'high'
  },
  {
    pattern: /dbms_xmlquery/i,
    dialect: ['oracle'],
    context: ['xml-injection'],
    severity: 'high'
  },
  {
    pattern: /information_schema/i,
    dialect: ['mysql', 'postgresql', 'mssql'],
    context: ['schema-enumeration'],
    severity: 'medium'
  },
  {
    pattern: /sys\.(tables|columns|databases)/i,
    dialect: ['mssql'],
    context: ['schema-enumeration'],
    severity: 'medium'
  },
  {
    pattern: /all_tables|all_columns/i,
    dialect: ['oracle'],
    context: ['schema-enumeration'],
    severity: 'medium'
  },
  {
    pattern: /version\(\)/i,
    dialect: ['mysql', 'postgresql'],
    context: ['version-enumeration'],
    severity: 'low'
  },
  {
    pattern: /@@version/i,
    dialect: ['mssql', 'mysql'],
    context: ['version-enumeration'],
    severity: 'low'
  },
  {
    pattern: /version\s+from\s+v\$instance/i,
    dialect: ['oracle'],
    context: ['version-enumeration'],
    severity: 'low'
  },
  {
    pattern: /ORDER\s+BY\s+\d+/i,
    dialect: ['mysql', 'postgresql', 'sqlite', 'mssql', 'oracle'],
    context: ['column-enumeration'],
    severity: 'low'
  },
  {
    pattern: /GROUP\s+BY\s+.*HAVING/i,
    dialect: ['mysql', 'postgresql', 'mssql', 'oracle'],
    context: ['having-clause'],
    severity: 'medium'
  },
  {
    pattern: /CAST\s*\(.*\s+AS\s+/i,
    dialect: ['mysql', 'postgresql', 'mssql', 'oracle'],
    context: ['type-casting'],
    severity: 'medium'
  },
  {
    pattern: /CONVERT\s*\(.*,/i,
    dialect: ['mysql', 'mssql'],
    context: ['type-casting'],
    severity: 'medium'
  },
  {
    pattern: /CHAR\s*\(\s*\d+.*\)/i,
    dialect: ['mysql', 'mssql'],
    context: ['string-encoding'],
    severity: 'medium'
  },
  {
    pattern: /CHR\s*\(\s*\d+.*\)/i,
    dialect: ['oracle', 'postgresql'],
    context: ['string-encoding'],
    severity: 'medium'
  }
];

export const SQL_SECURITY_RULES: SecurityRule[] = [
  {
    id: 'SQL-001',
    name: 'SQL Injection - String Concatenation',
    description: 'Potential SQL injection vulnerability through string concatenation',
    severity: 'critical',
    category: 'sql-injection' as SecurityCategory,
    owaspCategory: 'A03:2021-Injection' as OwaspCategory,
    fileTypes: ['sql', 'javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'go', 'csharp'],
    patterns: [
      /["']\s*\+\s*\w+.*?\+\s*["']/,
      /\$\{[^}]+\}/,
      /%s/,
      /\?\?/,
      /\{[0-9]\}/
    ],
    message: 'Potential SQL injection through string concatenation or interpolation. Use parameterized queries instead.',
    remediation: 'Use parameterized queries/prepared statements instead of string concatenation. Example: `db.query("SELECT * FROM users WHERE id = ?", [userId])`',
    references: [
      'https://owasp.org/www-project-top-ten/2017/A1_2017-Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
    ]
  },
  {
    id: 'SQL-002',
    name: 'Hardcoded SQL Credentials',
    description: 'Database credentials found hardcoded in SQL or configuration',
    severity: 'critical',
    category: 'hardcoded-secrets' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['sql', 'properties', 'yaml', 'json', 'xml', 'ini', 'env'],
    patterns: [
      /password\s*=\s*["'][^"']+["']/i,
      /passwd\s*=\s*["'][^"']+["']/i,
      /pwd\s*=\s*["'][^"']+["']/i,
      /user\s*=\s*["'][^"']+["'].*password/i,
      /IDENTIFIED\s+BY\s+["'][^"']+["']/i
    ],
    negativePatterns: [
      /password\s*=\s*["']\$\{/,
      /password\s*=\s*["']\$\w+/,
      /password\s*=\s*["']process\.env/
    ],
    message: 'Hardcoded database credentials detected. Never store credentials in source code.',
    remediation: 'Use environment variables, secret management tools, or configuration files excluded from version control.',
    references: [
      'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication',
      'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'
    ]
  },
  {
    id: 'SQL-003',
    name: 'Dangerous SQL Functions',
    description: 'Use of dangerous SQL functions that can lead to code execution',
    severity: 'high',
    category: 'sql-injection' as SecurityCategory,
    owaspCategory: 'A03:2021-Injection' as OwaspCategory,
    fileTypes: ['sql'],
    patterns: [
      /xp_cmdshell/i,
      /xp_regread/i,
      /xp_regwrite/i,
      /xp_fileexist/i,
      /sp_oamethod/i,
      /sp_oacreate/i,
      /LOAD_FILE\s*\(/i,
      /INTO\s+OUTFILE/i,
      /INTO\s+DUMPFILE/i,
      /UTL_HTTP\./i,
      /UTL_FILE\./i,
      /DBMS_XMLQUERY/i,
      /DBMS_XMLGEN/i
    ],
    message: 'Dangerous SQL function detected that could enable code execution or file system access.',
    remediation: 'Avoid using dangerous extended stored procedures. Use proper access controls and least privilege principles.',
    references: [
      'https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql'
    ]
  },
  {
    id: 'SQL-004',
    name: 'SQL Wildcard Injection',
    description: 'Potential SQL injection through LIKE wildcards',
    severity: 'medium',
    category: 'sql-injection' as SecurityCategory,
    owaspCategory: 'A03:2021-Injection' as OwaspCategory,
    fileTypes: ['sql', 'javascript', 'typescript', 'python', 'java', 'php'],
    patterns: [
      /LIKE\s+["']?%?\$\{/i,
      /LIKE\s+["']?%?\$/i,
      /LIKE\s+["']%?\{.*\}%?["']/i
    ],
    message: 'SQL LIKE clause with potential wildcard injection. Special characters may not be properly escaped.',
    remediation: 'Escape special LIKE characters (%, _, [, ]) or use parameterized queries.',
    references: [
      'https://owasp.org/www-community/attacks/SQL_Injection'
    ]
  },
  {
    id: 'SQL-005',
    name: 'Second-Order SQL Injection',
    description: 'Potential second-order SQL injection through stored data',
    severity: 'high',
    category: 'sql-injection' as SecurityCategory,
    owaspCategory: 'A03:2021-Injection' as OwaspCategory,
    fileTypes: ['sql', 'javascript', 'typescript', 'python', 'java', 'php', 'ruby'],
    patterns: [
      /INSERT.*SELECT.*FROM.*WHERE/i,
      /UPDATE.*SET.*=.*\(.*SELECT/i
    ],
    message: 'Potential second-order SQL injection. Data from database is used in subsequent queries without sanitization.',
    remediation: 'Always use parameterized queries even when using data from the database.',
    references: [
      'https://owasp.org/www-community/attacks/Second_Order_SQL_Injection'
    ]
  },
  {
    id: 'SQL-006',
    name: 'NoSQL Injection',
    description: 'Potential NoSQL injection vulnerability',
    severity: 'critical',
    category: 'sql-injection' as SecurityCategory,
    owaspCategory: 'A03:2021-Injection' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby'],
    patterns: [
      /\.find\s*\(\s*\{.*\$where.*:/,
      /\.find\s*\(\s*\{.*\$regex.*:/,
      /\$where.*:.*["'].*\+/,
      /db\.\w+\.find\s*\(\s*["'].*\$/,
      /\{.*\$ne.*:.*null.*\}/
    ],
    message: 'Potential NoSQL injection detected. User input may be used in query operators.',
    remediation: 'Use proper input validation and avoid using user input directly in NoSQL query operators.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection'
    ]
  }
];
