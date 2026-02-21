import { SecurityRule, SecurityCategory, OwaspCategory, SeverityLevel } from '../../types';

export const OWASP_TOP10_RULES: SecurityRule[] = [
  // A01:2021-Broken Access Control
  {
    id: 'OWASP-A01-001',
    name: 'Insecure Direct Object Reference (IDOR)',
    description: 'Potential IDOR vulnerability allowing unauthorized access to resources',
    severity: 'high' as SeverityLevel,
    category: 'access-control' as SecurityCategory,
    owaspCategory: 'A01:2021-Broken Access Control' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'go', 'csharp'],
    patterns: [
      /req\.params\.\w+.*findById/i,
      /req\.query\.\w+.*findOne/i,
      /request\.GET\[.*\].*get\(/i,
      /params\[:\w+\].*find/i,
      /id\s*=\s*params\[/i
    ],
    message: 'Potential IDOR vulnerability: User-supplied identifier used to access resources without authorization checks.',
    remediation: 'Implement proper authorization checks before accessing resources based on user-supplied identifiers.',
    references: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html'
    ]
  },
  {
    id: 'OWASP-A01-002',
    name: 'Missing Authentication Check',
    description: 'Endpoint or function missing authentication verification',
    severity: 'high' as SeverityLevel,
    category: 'authentication' as SecurityCategory,
    owaspCategory: 'A01:2021-Broken Access Control' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp'],
    patterns: [
      /app\.(get|post|put|delete|patch)\s*\([^)]*\)\s*=>\s*\{/,
      /@app\.route.*methods/i,
      /function\s+\w+\s*\([^)]*\)\s*\{(?!\s*.*auth)/i
    ],
    negativePatterns: [
      /auth/i,
      /require_auth/i,
      /authenticate/i,
      /login_required/i,
      /@PreAuthorize/
    ],
    message: 'Route or function may be missing authentication check.',
    remediation: 'Add authentication middleware or decorators to protect routes and functions.',
    references: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
    ]
  },
  {
    id: 'OWASP-A01-003',
    name: 'Directory Traversal',
    description: 'Potential path traversal vulnerability allowing file system access',
    severity: 'high' as SeverityLevel,
    category: 'path-traversal' as SecurityCategory,
    owaspCategory: 'A01:2021-Broken Access Control' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'go', 'csharp'],
    patterns: [
      /fs\.readFile.*req\.(query|params|body)/i,
      /open\s*\(\s*.*\+\s*request/i,
      /file_get_contents\s*\(\s*\$_/i,
      /Path\s*\(\s*.*request/i,
      /send_file.*request/i,
      /\.\/\.\.\/|\.\.\\\.\\/
    ],
    message: 'Potential directory traversal vulnerability. User input used in file path construction.',
    remediation: 'Use allowlist-based path validation, sanitize user input, and use chroot jails where possible.',
    references: [
      'https://owasp.org/www-community/attacks/Path_Traversal',
      'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'
    ]
  },

  // A02:2021-Cryptographic Failures
  {
    id: 'OWASP-A02-001',
    name: 'Weak Hashing Algorithm',
    description: 'Use of weak or deprecated cryptographic hashing algorithm',
    severity: 'high' as SeverityLevel,
    category: 'weak-cryptography' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp', 'go'],
    patterns: [
      /md5\s*\(/i,
      /sha1\s*\(/i,
      /MD5\s*\(/,
      /SHA1\s*\(/,
      /\.createHash\s*\(\s*["']md5["']\s*\)/,
      /\.createHash\s*\(\s*["']sha1["']\s*\)/,
      /hashlib\.md5\s*\(/,
      /hashlib\.sha1\s*\(/,
      /MessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)/,
      /MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\s*\)/
    ],
    message: 'Weak hashing algorithm (MD5 or SHA1) detected. These algorithms are cryptographically broken.',
    remediation: 'Use strong hashing algorithms like SHA-256, SHA-3, or bcrypt/Argon2 for password hashing.',
    references: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'
    ]
  },
  {
    id: 'OWASP-A02-002',
    name: 'Hardcoded Encryption Key',
    description: 'Encryption key hardcoded in source code',
    severity: 'critical' as SeverityLevel,
    category: 'hardcoded-secrets' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp', 'go'],
    patterns: [
      /key\s*=\s*["']{10,}["']/i,
      /secret\s*=\s*["']{16,}["']/i,
      /encryption_key\s*=\s*["'][^"']+["']/i,
      /AES_KEY\s*=\s*["'][^"']+["']/i,
      /PRIVATE_KEY\s*=\s*["'][^"']+["']/i
    ],
    negativePatterns: [
      /process\.env/,
      /os\.environ/,
      /System\.getenv/,
      /getenv/,
      /config\.get/
    ],
    message: 'Hardcoded encryption key detected. Never hardcode cryptographic keys.',
    remediation: 'Use secure key management systems, environment variables, or hardware security modules (HSMs).',
    references: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
    ]
  },
  {
    id: 'OWASP-A02-003',
    name: 'Insecure Randomness',
    description: 'Use of insecure random number generator for security purposes',
    severity: 'medium' as SeverityLevel,
    category: 'weak-cryptography' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp'],
    patterns: [
      /Math\.random\s*\(\s*\)/,
      /random\.random\s*\(\s*\)/,
      /Random\s*\(\s*\)/,
      /srand\s*\(/,
      /rand\s*\(\s*\)/,
      /Random\.Next\s*\(\s*\)/
    ],
    message: 'Insecure random number generator used. Not suitable for security purposes.',
    remediation: 'Use cryptographically secure random number generators like crypto.randomBytes, secrets.token_hex, or SecureRandom.',
    references: [
      'https://owasp.org/www-community/vulnerabilities/Insecure_Randomness'
    ]
  },
  {
    id: 'OWASP-A02-004',
    name: 'Weak SSL/TLS Configuration',
    description: 'Weak or insecure SSL/TLS configuration detected',
    severity: 'high' as SeverityLevel,
    category: 'weak-cryptography' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['yaml', 'yml', 'json', 'xml', 'properties', 'conf'],
    patterns: [
      /ssl_version.*TLSv1(?!\.2|\.3)/i,
      /TLSv1\.(0|1)(?!\.\d)/i,
      /SSLv(2|3)/i,
      /RC4/i,
      /DES(?!3)/i,
      /3DES/i,
      /MD5.*signature/i,
      /verify_mode.*NONE/i,
      /InsecureSkipVerify.*true/i,
      /rejectUnauthorized.*false/i
    ],
    message: 'Weak SSL/TLS configuration detected. Using deprecated protocols or ciphers.',
    remediation: 'Use TLS 1.2 or higher only. Disable weak ciphers and enable certificate verification.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security'
    ]
  },

  // A03:2021-Injection (SQL covered separately)
  {
    id: 'OWASP-A03-001',
    name: 'Command Injection',
    description: 'Potential command injection vulnerability',
    severity: 'critical' as SeverityLevel,
    category: 'command-injection' as SecurityCategory,
    owaspCategory: 'A03:2021-Injection' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'go', 'csharp', 'shell'],
    patterns: [
      /exec\s*\(\s*.*\+\s*/i,
      /execSync\s*\(\s*.*\$/,
      /child_process.*exec.*\$/,
      /os\.system\s*\(\s*.*\+/,
      /subprocess\.call\s*\(\s*.*shell\s*=\s*True/i,
      /eval\s*\(\s*.*req\./i,
      /Runtime\.getRuntime\(\)\.exec/i,
      /system\s*\(\s*\$_/i,
      /`[^`]*\$\{[^}]*\}[^`]*`/,
      /backtick.*\$\{/i
    ],
    message: 'Potential command injection. User input used in command execution.',
    remediation: 'Use parameterized APIs, avoid shell execution, and validate/sanitize all user input.',
    references: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'
    ]
  },
  {
    id: 'OWASP-A03-002',
    name: 'LDAP Injection',
    description: 'Potential LDAP injection vulnerability',
    severity: 'high' as SeverityLevel,
    category: 'injection' as SecurityCategory,
    owaspCategory: 'A03:2021-Injection' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'csharp'],
    patterns: [
      /ldap.*search.*\+/i,
      /ldap.*filter.*\$/i,
      /DirContext.*search.*\+/i,
      /ldap_search.*\$_/i
    ],
    message: 'Potential LDAP injection. User input used in LDAP query construction.',
    remediation: 'Use parameterized LDAP queries and escape special characters.',
    references: [
      'https://owasp.org/www-community/attacks/LDAP_Injection'
    ]
  },
  {
    id: 'OWASP-A03-003',
    name: 'XPath Injection',
    description: 'Potential XPath injection vulnerability',
    severity: 'high' as SeverityLevel,
    category: 'injection' as SecurityCategory,
    owaspCategory: 'A03:2021-Injection' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'csharp'],
    patterns: [
      /xpath.*compile.*\+/i,
      /xpath.*evaluate.*\$/i,
      /XPathExpression.*\+/i
    ],
    message: 'Potential XPath injection. User input used in XPath expression.',
    remediation: 'Use parameterized XPath queries and validate input against allowlist.',
    references: [
      'https://owasp.org/www-community/attacks/XPATH_Injection'
    ]
  },
  {
    id: 'OWASP-A03-004',
    name: 'XML External Entity (XXE)',
    description: 'Potential XXE vulnerability in XML parsing',
    severity: 'critical' as SeverityLevel,
    category: 'injection' as SecurityCategory,
    owaspCategory: 'A03:2021-Injection' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'csharp'],
    patterns: [
      /DOMParser\s*\(\s*\).*parseFromString/i,
      /xml2js\.parseString/i,
      /DocumentBuilder\.parse/i,
      /XMLReader/i,
      /SAXPARSER/i,
      /simplexml_load_string/i,
      /loadXML/i,
      /parseXML/i
    ],
    negativePatterns: [
      /setFeature.*FEATURE_SECURE_PROCESSING/i,
      /setFeature.*disallow-doctype-decl/i,
      /noent.*false/i
    ],
    message: 'Potential XXE vulnerability. XML parser may process external entities.',
    remediation: 'Disable external entity processing and DTDs in XML parsers.',
    references: [
      'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
      'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'
    ]
  },

  // A05:2021-Security Misconfiguration
  {
    id: 'OWASP-A05-001',
    name: 'Debug Mode Enabled',
    description: 'Application running in debug mode in production',
    severity: 'high' as SeverityLevel,
    category: 'insecure-configuration' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'json', 'yaml', 'yml', 'properties', 'env'],
    patterns: [
      /debug\s*:\s*true/i,
      /DEBUG\s*=\s*True/i,
      /DEBUG\s*=\s*["']?true["']?/i,
      /APP_DEBUG\s*=\s*true/i,
      /NODE_ENV\s*=\s*["']?development["']?/i
    ],
    message: 'Debug mode appears to be enabled. Never run in debug mode in production.',
    remediation: 'Set debug mode to false in production environments.',
    references: [
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  {
    id: 'OWASP-A05-002',
    name: 'CORS Misconfiguration',
    description: 'Overly permissive CORS configuration',
    severity: 'medium' as SeverityLevel,
    category: 'insecure-configuration' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'yaml', 'json'],
    patterns: [
      /Access-Control-Allow-Origin.*\*/i,
      /cors.*origin.*\*/i,
      /Access-Control-Allow-Origin.*null/i,
      /\.cors\s*\(\s*\{\s*origin.*\*/
    ],
    message: 'Permissive CORS configuration allowing any origin to access resources.',
    remediation: 'Specify explicit allowed origins instead of using wildcard (*) or null.',
    references: [
      'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'
    ]
  },
  {
    id: 'OWASP-A05-003',
    name: 'Exposed Sensitive Headers',
    description: 'Sensitive headers exposed in HTTP responses',
    severity: 'medium' as SeverityLevel,
    category: 'insecure-configuration' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'yaml', 'json', 'conf'],
    patterns: [
      /server_tokens\s+on/i,
      /expose_php\s+on/i,
      /X-Powered-By/i,
      /Server.*Apache/i,
      /Server.*nginx/i
    ],
    message: 'Server version information exposed in HTTP headers.',
    remediation: 'Disable server tokens and remove version information from HTTP headers.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server'
    ]
  },

  // A06:2021-Vulnerable and Outdated Components
  {
    id: 'OWASP-A06-001',
    name: 'Vulnerable Dependency Version',
    description: 'Potentially vulnerable dependency version',
    severity: 'high' as SeverityLevel,
    category: 'dependency-vulnerability' as SecurityCategory,
    owaspCategory: 'A06:2021-Vulnerable and Outdated Components' as OwaspCategory,
    fileTypes: ['json', 'xml', 'toml', 'yaml'],
    patterns: [
      /"lodash":\s*"[<~]?4\.17\.\d/,
      /"jquery":\s*"[<~]?3\.4\.\d/,
      /"bootstrap":\s*"[<~]?4\.3\.\d/
    ],
    message: 'Potentially vulnerable dependency version detected.',
    remediation: 'Update to the latest stable version of the dependency.',
    references: [
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
    ]
  },

  // A07:2021-Identification and Authentication Failures
  {
    id: 'OWASP-A07-001',
    name: 'Weak Password Policy',
    description: 'Weak password policy or validation',
    severity: 'medium' as SeverityLevel,
    category: 'authentication' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp'],
    patterns: [
      /password.*min.*length.*[{]?[0-5][}]?/i,
      /min.*password.*length.*[0-5]/i,
      /password.*.{0,5}\}/,
      /validate_password.*.{0,5}/i
    ],
    message: 'Password policy may be too weak (less than 8 characters).',
    remediation: 'Enforce strong password policies: minimum 12 characters, mixed case, numbers, and special characters.',
    references: [
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
    ]
  },
  {
    id: 'OWASP-A07-002',
    name: 'Insecure Session Configuration',
    description: 'Insecure session management configuration',
    severity: 'high' as SeverityLevel,
    category: 'authentication' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'yaml', 'json'],
    patterns: [
      /cookie.*secure.*false/i,
      /cookie.*httponly.*false/i,
      /session\.cookie\.secure\s*=\s*false/i,
      /SESSION_COOKIE_HTTPONLY\s*=\s*False/i,
      /sameSite.*none/i,
      /session.*timeout.*\d{1,3}[^0-9]/
    ],
    message: 'Insecure session cookie configuration detected.',
    remediation: 'Set Secure, HttpOnly, and SameSite flags on session cookies. Use appropriate session timeouts.',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'
    ]
  },
  {
    id: 'OWASP-A07-003',
    name: 'Hardcoded Credentials',
    description: 'Hardcoded username or password detected',
    severity: 'critical' as SeverityLevel,
    category: 'hardcoded-secrets' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp', 'go', 'yaml', 'json', 'properties'],
    patterns: [
      /admin["']?\s*:\s*["']admin["']/i,
      /username\s*=\s*["']admin["']/i,
      /password\s*=\s*["']password["']/i,
      /password\s*=\s*["']123456["']/i,
      /default.*password/i
    ],
    message: 'Hardcoded default credentials detected.',
    remediation: 'Remove default credentials and require strong authentication setup.',
    references: [
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
    ]
  },

  // A08:2021-Software and Data Integrity Failures
  {
    id: 'OWASP-A08-001',
    name: 'Insecure Deserialization',
    description: 'Potential insecure deserialization vulnerability',
    severity: 'critical' as SeverityLevel,
    category: 'input-validation' as SecurityCategory,
    owaspCategory: 'A08:2021-Software and Data Integrity Failures' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp'],
    patterns: [
      /eval\s*\(\s*.*JSON\.parse/i,
      /pickle\.loads\s*\(/,
      /ObjectInputStream.*readObject/i,
      /unserialize\s*\(\s*\$_/i,
      /YAML\.load\s*\(/,
      /\.from_yaml\s*\(/i
    ],
    negativePatterns: [
      /yaml\.safe_load/i,
      /SafeLoader/i,
      /JSON\.parse.*catch/
    ],
    message: 'Potential insecure deserialization. Untrusted data being deserialized.',
    remediation: 'Use safe deserialization methods, implement integrity checks, and run deserialization in isolated environments.',
    references: [
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'
    ]
  },
  {
    id: 'OWASP-A08-002',
    name: 'Missing Subresource Integrity',
    description: 'External resource loaded without integrity check',
    severity: 'medium' as SeverityLevel,
    category: 'data-validation' as SecurityCategory,
    owaspCategory: 'A08:2021-Software and Data Integrity Failures' as OwaspCategory,
    fileTypes: ['html', 'javascript', 'typescript'],
    patterns: [
      /<script\s+src\s*=\s*["']https?:\/\//i,
      /<link\s+rel\s*=\s*["']stylesheet["'].*href\s*=\s*["']https?:\/\//i
    ],
    negativePatterns: [
      /integrity\s*=/i,
      /crossorigin/i
    ],
    message: 'External resource loaded without Subresource Integrity (SRI) hash.',
    remediation: 'Add integrity attribute with cryptographic hash for all external resources.',
    references: [
      'https://owasp.org/www-community/controls/Subresource_Integrity'
    ]
  },

  // A09:2021-Security Logging and Monitoring Failures
  {
    id: 'OWASP-A09-001',
    name: 'Sensitive Data in Logs',
    description: 'Potentially sensitive data being logged',
    severity: 'high' as SeverityLevel,
    category: 'logging' as SecurityCategory,
    owaspCategory: 'A09:2021-Security Logging and Monitoring Failures' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp'],
    patterns: [
      /console\.log.*password/i,
      /console\.log.*token/i,
      /console\.log.*secret/i,
      /logger\.(info|debug|warn|error).*password/i,
      /logger\.(info|debug|warn|error).*credit.*card/i,
      /print.*password/i,
      /System\.out\.print.*password/i,
      /log\s*\(\s*.*password/i
    ],
    message: 'Sensitive data may be logged. Avoid logging passwords, tokens, or PII.',
    remediation: 'Implement data masking and filtering for sensitive information in logs.',
    references: [
      'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'
    ]
  },
  {
    id: 'OWASP-A09-002',
    name: 'Missing Error Handling',
    description: 'Exception or error without proper handling',
    severity: 'medium' as SeverityLevel,
    category: 'error-handling' as SecurityCategory,
    owaspCategory: 'A09:2021-Security Logging and Monitoring Failures' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'csharp'],
    patterns: [
      /catch\s*\([^)]*\)\s*\{\s*\}/,
      /catch\s*\([^)]*\)\s*\{[\s]*\/\/.*ignore/i,
      /pass\s*#.*ignore/i,
      /catch.*\{\s*\/\/.*do nothing/i,
      /rescue\s*=>.*\w+\s*#.*ignore/i
    ],
    message: 'Empty or ignored exception handling detected.',
    remediation: 'Implement proper error handling and logging for all exceptions.',
    references: [
      'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
    ]
  },

  // A10:2021-Server-Side Request Forgery (SSRF)
  {
    id: 'OWASP-A10-001',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Potential SSRF vulnerability',
    severity: 'high' as SeverityLevel,
    category: 'network-security' as SecurityCategory,
    owaspCategory: 'A10:2021-Server-Side Request Forgery (SSRF)' as OwaspCategory,
    fileTypes: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp'],
    patterns: [
      /fetch\s*\(\s*.*req\.(query|params|body)/i,
      /axios\.(get|post)\s*\(\s*.*req\./i,
      /requests\.(get|post)\s*\(\s*.*request/i,
      /urllib\.request\.urlopen\s*\(\s*.*\+/i,
      /curl_exec\s*\(\s*\$_/i,
      /open-uri/i,
      /HttpClient.*GetString/i
    ],
    negativePatterns: [
      /allowlist/i,
      /whitelist/i,
      /validate.*url/i,
      /isValidUrl/i
    ],
    message: 'Potential SSRF vulnerability. User input used to construct URLs for server-side requests.',
    remediation: 'Validate and sanitize all URLs, use allowlists, and disable unnecessary URL schemes.',
    references: [
      'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
    ]
  },
  {
    id: 'OWASP-A10-002',
    name: 'File Inclusion Vulnerability',
    description: 'Potential file inclusion or path traversal in URL fetching',
    severity: 'high' as SeverityLevel,
    category: 'path-traversal' as SecurityCategory,
    owaspCategory: 'A10:2021-Server-Side Request Forgery (SSRF)' as OwaspCategory,
    fileTypes: ['php', 'javascript', 'typescript', 'python', 'java'],
    patterns: [
      /include\s*\(\s*\$_/i,
      /require\s*\(\s*\$_/i,
      /include_once\s*\(\s*\$_/i,
      /file\s*\(\s*\$_/i,
      /readfile\s*\(\s*\$_/i
    ],
    message: 'Potential file inclusion vulnerability. User input used in file inclusion.',
    remediation: 'Use allowlists for allowed files, avoid dynamic file inclusion, and validate file paths.',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion'
    ]
  }
];

export const ALL_OWASP_RULES: SecurityRule[] = OWASP_TOP10_RULES;
