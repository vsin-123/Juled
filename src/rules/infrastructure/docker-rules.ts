import { SecurityRule, SecurityCategory, OwaspCategory, SeverityLevel } from '../../types';

export const DOCKERFILE_SECURITY_RULES: SecurityRule[] = [
  // Base Image Rules
  {
    id: 'DOCKER-001',
    name: 'Latest Tag Used',
    description: 'Docker image uses "latest" tag which can lead to unpredictable builds',
    severity: 'medium' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A06:2021-Vulnerable and Outdated Components' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /FROM\s+\w+\/\w+:latest/i,
      /FROM\s+\w+:latest/i
    ],
    message: 'Using "latest" tag for base image can lead to unpredictable builds and security issues.',
    remediation: 'Use specific version tags (e.g., node:18.17-alpine3.18) for reproducible and secure builds.',
    references: [
      'https://docs.docker.com/develop/dev-best-practices/dockerfile_best-practices/#pin-base-image-versions',
      'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html'
    ]
  },
  {
    id: 'DOCKER-002',
    name: 'Vulnerable Base Image',
    description: 'Using potentially vulnerable base image versions',
    severity: 'high' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A06:2021-Vulnerable and Outdated Components' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /FROM\s+.*:alpine3\.[0-9](?!\d)/i,
      /FROM\s+node:1[0-4]\./i,
      /FROM\s+python:2\./i,
      /FROM\s+.*:trusty/i,
      /FROM\s+.*:xenial/i,
      /FROM\s+.*:jessie/i
    ],
    message: 'Using potentially outdated or end-of-life base image version.',
    remediation: 'Update to the latest stable version of the base image.',
    references: [
      'https://docs.docker.com/develop/dev-best-practices/dockerfile_best-practices/',
      'https://endoflife.date/'
    ]
  },
  {
    id: 'DOCKER-003',
    name: 'Full OS Image Used',
    description: 'Using full OS image instead of minimal base image',
    severity: 'low' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /FROM\s+ubuntu:(?!.*slim)/i,
      /FROM\s+debian:(?!.*slim)/i,
      /FROM\s+centos:/i,
      /FROM\s+fedora:/i
    ],
    negativePatterns: [
      /slim/
    ],
    message: 'Using full OS image increases attack surface. Consider using minimal images.',
    remediation: 'Use slim, alpine, or distroless variants of base images.',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-1---prefer-minimal-base-images'
    ]
  },

  // User Privilege Rules
  {
    id: 'DOCKER-004',
    name: 'Running as Root',
    description: 'Container runs as root user',
    severity: 'high' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /USER\s+root/i,
      /^(?!.*USER\s+(?!root)).*/s
    ],
    negativePatterns: [
      /USER\s+(?!root)/i
    ],
    message: 'Container does not switch to non-root user. Running as root increases security risk.',
    remediation: 'Add a non-root user and switch to it using USER instruction.',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-2---create-a-non-root-user',
      'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user'
    ]
  },

  // Secrets and Credentials
  {
    id: 'DOCKER-005',
    name: 'Hardcoded Secret in Dockerfile',
    description: 'Secret or credential hardcoded in Dockerfile',
    severity: 'critical' as SeverityLevel,
    category: 'hardcoded-secrets' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /ENV\s+\w*(PASSWORD|SECRET|TOKEN|KEY|API_KEY)\w*\s*=\s*[^\s]+/i,
      /ARG\s+\w*(PASSWORD|SECRET|TOKEN|KEY|API_KEY)\w*\s*=\s*[^\s]+/i,
      /RUN\s+.*curl.*-[uU]\s+[^:]+:[^\s]+/i,
      /echo\s+["']?\w*password\w*["']?\s*>>/i
    ],
    message: 'Hardcoded secret detected in Dockerfile. Secrets in Docker layers can be exposed.',
    remediation: 'Use Docker secrets, BuildKit secrets, or pass secrets at runtime via environment variables.',
    references: [
      'https://docs.docker.com/engine/swarm/secrets/',
      'https://docs.docker.com/develop/develop-images/build_enhancements/#new-docker-build-secret-information'
    ]
  },
  {
    id: 'DOCKER-006',
    name: 'SSH Private Key in Image',
    description: 'SSH private key may be added to Docker image',
    severity: 'critical' as SeverityLevel,
    category: 'hardcoded-secrets' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /ADD\s+.*id_rsa/i,
      /ADD\s+.*\.ssh/i,
      /COPY\s+.*id_rsa/i,
      /COPY\s+.*\.ssh/i,
      /RUN\s+.*ssh-keygen/i,
      /-----BEGIN\s+(RSA|OPENSSH|EC)\s+PRIVATE\s+KEY-----/
    ],
    message: 'SSH private key may be included in Docker image. This is a critical security risk.',
    remediation: 'Use Docker BuildKit SSH forwarding or multi-stage builds to avoid including keys.',
    references: [
      'https://docs.docker.com/develop/develop-images/build_enhancements/#using-ssh-to-access-private-data-in-builds'
    ]
  },

  // Package Management Rules
  {
    id: 'DOCKER-007',
    name: 'apt-get Without No-Install-Recommends',
    description: 'apt-get install without --no-install-recommends flag',
    severity: 'low' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /RUN\s+apt-get\s+install\s+(?!.*--no-install-recommends)/i
    ],
    message: 'apt-get install without --no-install-recommends installs unnecessary packages.',
    remediation: 'Use --no-install-recommends to reduce image size and attack surface.',
    references: [
      'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#apt-get'
    ]
  },
  {
    id: 'DOCKER-008',
    name: 'apt-get Update Without Install',
    description: 'apt-get update not combined with install in same RUN',
    severity: 'low' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /RUN\s+apt-get\s+update\s*$/m
    ],
    message: 'apt-get update should be combined with install in same RUN to avoid cache issues.',
    remediation: 'Combine apt-get update and install in single RUN instruction with &&.',
    references: [
      'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#apt-get'
    ]
  },
  {
    id: 'DOCKER-009',
    name: 'No Package Version Pinning',
    description: 'Package installation without version pinning',
    severity: 'medium' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A06:2021-Vulnerable and Outdated Components' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /apt-get\s+install\s+-y\s+\w+\s/,
      /pip\s+install\s+\w+\s/,
      /npm\s+install\s+-g\s+\w+\s/,
      /gem\s+install\s+\w+\s/
    ],
    negativePatterns: [
      /==\d/,
      /@\d/,
      /=\d/
    ],
    message: 'Package installation without version pinning can lead to inconsistent builds.',
    remediation: 'Pin package versions (e.g., package==1.2.3) for reproducible builds.',
    references: [
      'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#apt-get'
    ]
  },

  // Network and Port Rules
  {
    id: 'DOCKER-010',
    name: 'Exposing Sensitive Ports',
    description: 'Sensitive ports exposed in Dockerfile',
    severity: 'medium' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /EXPOSE\s+22/,
      /EXPOSE\s+3389/,
      /EXPOSE\s+23/,
      /EXPOSE\s+21/,
      /EXPOSE\s+1433/,
      /EXPOSE\s+3306/,
      /EXPOSE\s+5432/
    ],
    message: 'Sensitive service port exposed. Consider if this port needs to be exposed.',
    remediation: 'Only expose ports that are necessary for the application to function.',
    references: [
      'https://docs.docker.com/engine/reference/builder/#expose'
    ]
  },

  // Health Check Rules
  {
    id: 'DOCKER-011',
    name: 'No Health Check Defined',
    description: 'Dockerfile does not define HEALTHCHECK',
    severity: 'low' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A09:2021-Security Logging and Monitoring Failures' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /^(?!.*HEALTHCHECK).*$/s
    ],
    negativePatterns: [
      /HEALTHCHECK/i
    ],
    message: 'No HEALTHCHECK instruction found. Container health cannot be monitored.',
    remediation: 'Add a HEALTHCHECK instruction to monitor container health.',
    references: [
      'https://docs.docker.com/engine/reference/builder/#healthcheck'
    ]
  },

  // Security Options
  {
    id: 'DOCKER-012',
    name: 'ADD Instead of COPY',
    description: 'Using ADD instead of COPY for local files',
    severity: 'low' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /ADD\s+[^\s]+\s+[^\s]+/
    ],
    negativePatterns: [
      /ADD\s+https?:\/\//,
      /ADD\s+.*\.tar/
    ],
    message: 'Using ADD instead of COPY. ADD has more complex behavior and should be avoided for local files.',
    remediation: 'Use COPY for local files. Only use ADD for URLs and tar extraction.',
    references: [
      'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy'
    ]
  },
  {
    id: 'DOCKER-013',
    name: 'Sudo Usage',
    description: 'Using sudo in Dockerfile',
    severity: 'medium' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /RUN\s+sudo/i
    ],
    message: 'Using sudo in Dockerfile is unnecessary and can lead to security issues.',
    remediation: 'Remove sudo. RUN commands execute as root by default in Docker.',
    references: [
      'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user'
    ]
  },
  {
    id: 'DOCKER-014',
    name: 'Curl to Shell',
    description: 'Piping curl output directly to shell',
    severity: 'high' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A08:2021-Software and Data Integrity Failures' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /curl.*\|.*sh/i,
      /curl.*\|.*bash/i,
      /wget.*-.*\|.*sh/i,
      /wget.*-.*\|.*bash/i
    ],
    message: 'Piping curl/wget output directly to shell is dangerous and can execute malicious code.',
    remediation: 'Download files first, verify checksums, then execute separately.',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html'
    ]
  },
  {
    id: 'DOCKER-015',
    name: 'Writable Root Filesystem',
    description: 'Container filesystem may be writable',
    severity: 'medium' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /VOLUME\s+\[?\s*["']?\/[^"']*["']?\s*\]?/
    ],
    message: 'Volumes can make root filesystem writable. Consider using read-only root filesystem.',
    remediation: 'Use docker run --read-only flag or Kubernetes securityContext.readOnlyRootFilesystem.',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-8---set-filesystem-and-volumes-to-read-only'
    ]
  },

  // Label Rules
  {
    id: 'DOCKER-016',
    name: 'Missing Security Labels',
    description: 'Dockerfile missing security-related labels',
    severity: 'low' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A09:2021-Security Logging and Monitoring Failures' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /^(?!.*LABEL\s+\w*version)/s
    ],
    message: 'Consider adding LABEL instructions for image versioning and documentation.',
    remediation: 'Add LABEL instructions for version, description, maintainer, and security contact.',
    references: [
      'https://docs.docker.com/engine/reference/builder/#label'
    ]
  },

  // Workdir Rules
  {
    id: 'DOCKER-017',
    name: 'Relative Workdir',
    description: 'Using relative path in WORKDIR',
    severity: 'low' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /WORKDIR\s+(?!\/)/
    ],
    message: 'Using relative path in WORKDIR can be unpredictable.',
    remediation: 'Use absolute paths in WORKDIR instructions.',
    references: [
      'https://docs.docker.com/engine/reference/builder/#workdir'
    ]
  },

  // Multi-stage Build Rules
  {
    id: 'DOCKER-018',
    name: 'No Multi-Stage Build',
    description: 'Not using multi-stage builds to reduce image size',
    severity: 'low' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /^(?!.*FROM\s+.*AS).*FROM/s
    ],
    negativePatterns: [
      /FROM\s+.*AS/i
    ],
    message: 'Consider using multi-stage builds to reduce final image size and attack surface.',
    remediation: 'Use multi-stage builds to separate build dependencies from runtime.',
    references: [
      'https://docs.docker.com/develop/develop-images/multistage-build/'
    ]
  },

  // Certificate Rules
  {
    id: 'DOCKER-019',
    name: 'Certificate Verification Disabled',
    description: 'SSL/TLS certificate verification disabled',
    severity: 'high' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /NODE_TLS_REJECT_UNAUTHORIZED.*0/i,
      /PYTHONHTTPSVERIFY.*0/i,
      /curl.*-k/i,
      /curl.*--insecure/i,
      /wget.*--no-check-certificate/i,
      /git.*-c\s+http\.sslVerify=false/i
    ],
    message: 'SSL/TLS certificate verification is disabled. This exposes to MITM attacks.',
    remediation: 'Never disable certificate verification in production. Use proper certificates.',
    references: [
      'https://owasp.org/www-community/attacks/Man-in-the-middle_attack'
    ]
  },

  // .dockerignore Rules
  {
    id: 'DOCKER-020',
    name: 'Sensitive Files May Be Included',
    description: 'Potential sensitive files not excluded in .dockerignore',
    severity: 'medium' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['dockerfile'],
    patterns: [
      /COPY\s+\.\s+/,
      /ADD\s+\.\s+/
    ],
    message: 'Copying entire directory may include sensitive files. Ensure .dockerignore is properly configured.',
    remediation: 'Create a comprehensive .dockerignore file to exclude sensitive files.',
    references: [
      'https://docs.docker.com/engine/reference/builder/#dockerignore-file'
    ]
  }
];

export const DOCKER_COMPOSE_SECURITY_RULES: SecurityRule[] = [
  {
    id: 'COMPOSE-001',
    name: 'Privileged Container',
    description: 'Container running in privileged mode',
    severity: 'critical' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /privileged:\s*true/i
    ],
    message: 'Privileged container has full access to host resources. This is a major security risk.',
    remediation: 'Avoid privileged mode. Use specific capabilities with cap_add instead.',
    references: [
      'https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities'
    ]
  },
  {
    id: 'COMPOSE-002',
    name: 'Host Network Mode',
    description: 'Container using host network mode',
    severity: 'high' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /network_mode:\s*["']?host["']?/i
    ],
    message: 'Host network mode removes network isolation between container and host.',
    remediation: 'Use bridge network mode or user-defined networks for better isolation.',
    references: [
      'https://docs.docker.com/network/host/'
    ]
  },
  {
    id: 'COMPOSE-003',
    name: 'Host PID Namespace',
    description: 'Container sharing host PID namespace',
    severity: 'high' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /pid:\s*["']?host["']?/i
    ],
    message: 'Host PID namespace allows container to see and interact with host processes.',
    remediation: 'Use container PID namespace isolation unless specifically required.',
    references: [
      'https://docs.docker.com/engine/reference/run/#pid-settings---pid'
    ]
  },
  {
    id: 'COMPOSE-004',
    name: 'Sensitive Host Path Mounted',
    description: 'Sensitive host directory mounted into container',
    severity: 'critical' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /-\s*["']?\/:\/[^"']*["']?/,
      /-\s*["']?\/etc:\/[^"']*["']?/,
      /-\s*["']?\/root:\/[^"']*["']?/,
      /-\s*["']?\/var\/run\/docker\.sock:\/[^"']*["']?/,
      /-\s*["']?~\/\.ssh:\/[^"']*["']?/
    ],
    message: 'Sensitive host path mounted into container. This can lead to container escape.',
    remediation: 'Mount only specific directories needed by the application. Never mount Docker socket.',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html'
    ]
  },
  {
    id: 'COMPOSE-005',
    name: 'Writable Docker Socket Mount',
    description: 'Docker socket mounted without read-only option',
    severity: 'critical' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /-\s*["']?.*docker\.sock:\/[^"']*["']?/
    ],
    negativePatterns: [
      /:ro[\s"']?/
    ],
    message: 'Docker socket mounted without read-only flag grants full Docker access.',
    remediation: 'Avoid mounting Docker socket. If necessary, mount read-only with :ro flag.',
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html'
    ]
  },
  {
    id: 'COMPOSE-006',
    name: 'Environment Variables in Compose File',
    description: 'Sensitive data in docker-compose environment variables',
    severity: 'high' as SeverityLevel,
    category: 'hardcoded-secrets' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /environment:\s*\n(?:\s+-\s*\w*(PASSWORD|SECRET|TOKEN|KEY|API_KEY)\w*:\s*[^\n]+)/i
    ],
    message: 'Sensitive data hardcoded in docker-compose environment section.',
    remediation: 'Use .env files, secrets, or environment variable substitution instead.',
    references: [
      'https://docs.docker.com/compose/environment-variables/'
    ]
  },
  {
    id: 'COMPOSE-007',
    name: 'No Resource Limits',
    description: 'Container without resource limits',
    severity: 'medium' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /(?!.*deploy:\s*\n.*resources:).*services:/s
    ],
    negativePatterns: [
      /deploy:\s*\n.*resources:/s
    ],
    message: 'No resource limits configured for container. This can lead to DoS.',
    remediation: 'Set memory and CPU limits using deploy.resources in compose file.',
    references: [
      'https://docs.docker.com/compose/compose-file/compose-file-v3/#resources'
    ]
  },
  {
    id: 'COMPOSE-008',
    name: 'Capabilities Not Dropped',
    description: 'Container capabilities not explicitly dropped',
    severity: 'medium' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /^(?!.*cap_drop).*cap_add/s
    ],
    negativePatterns: [
      /cap_drop:/
    ],
    message: 'Container capabilities should explicitly drop ALL before adding specific ones.',
    remediation: 'Use cap_drop: [ALL] and then only add required capabilities with cap_add.',
    references: [
      'https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities'
    ]
  },
  {
    id: 'COMPOSE-009',
    name: 'No User Specified',
    description: 'Container running without explicit user',
    severity: 'medium' as SeverityLevel,
    category: 'container-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /^(?!.*user:).*image:/m
    ],
    negativePatterns: [
      /user:\s*\w+/i
    ],
    message: 'No user specified for container. May run as root.',
    remediation: 'Set user directive to run container as non-root user.',
    references: [
      'https://docs.docker.com/compose/compose-file/compose-file-v3/#domainname-hostname-ipc-mac_address-privileged-read_only-shm_size-stdin_open-tty-user-working_dir'
    ]
  },
  {
    id: 'COMPOSE-010',
    name: 'Secrets in Environment Variables',
    description: 'Docker secrets used incorrectly via environment',
    severity: 'high' as SeverityLevel,
    category: 'secrets-management' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /DB_PASSWORD|DATABASE_PASSWORD|POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|SECRET_KEY/i
    ],
    negativePatterns: [
      /secrets:/
    ],
    message: 'Database passwords should use Docker secrets, not environment variables.',
    remediation: 'Use Docker secrets or external secret management for sensitive data.',
    references: [
      'https://docs.docker.com/engine/swarm/secrets/'
    ]
  }
];
