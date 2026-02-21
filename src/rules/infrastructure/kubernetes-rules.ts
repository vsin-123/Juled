import { SecurityRule, SecurityCategory, OwaspCategory, SeverityLevel } from '../../types';

export const KUBERNETES_SECURITY_RULES: SecurityRule[] = [
  // Pod Security Rules
  {
    id: 'K8S-001',
    name: 'Privileged Container',
    description: 'Container running in privileged mode',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /privileged:\s*true/i,
      /securityContext:[\s\S]*?privileged:\s*true/i
    ],
    message: 'Privileged container has full access to host resources. This is a major security risk.',
    remediation: 'Set securityContext.privileged to false. Use specific capabilities if needed.',
    references: [
      'https://kubernetes.io/docs/concepts/security/pod-security-standards/',
      'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/'
    ]
  },
  {
    id: 'K8S-002',
    name: 'Host PID Namespace',
    description: 'Pod sharing host PID namespace',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /hostPID:\s*true/i
    ],
    message: 'Host PID namespace allows container to see and potentially interact with host processes.',
    remediation: 'Set hostPID to false or remove the field (defaults to false).',
    references: [
      'https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces'
    ]
  },
  {
    id: 'K8S-003',
    name: 'Host IPC Namespace',
    description: 'Pod sharing host IPC namespace',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /hostIPC:\s*true/i
    ],
    message: 'Host IPC namespace allows potential IPC communication with host processes.',
    remediation: 'Set hostIPC to false or remove the field.',
    references: [
      'https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces'
    ]
  },
  {
    id: 'K8S-004',
    name: 'Host Network Namespace',
    description: 'Pod using host network namespace',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /hostNetwork:\s*true/i
    ],
    message: 'Host network mode removes network isolation between pod and host.',
    remediation: 'Set hostNetwork to false. Use Kubernetes services and ingress for networking.',
    references: [
      'https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces'
    ]
  },
  {
    id: 'K8S-005',
    name: 'Running as Root',
    description: 'Container configured to run as root user',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /runAsUser:\s*0/,
      /runAsUser:\s*["']?0["']?/,
      /securityContext:[\s\S]*?runAsUser:\s*0/i
    ],
    message: 'Container is configured to run as root (UID 0).',
    remediation: 'Set runAsUser to a non-zero UID and runAsGroup to a non-zero GID.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod'
    ]
  },
  {
    id: 'K8S-006',
    name: 'Allow Privilege Escalation',
    description: 'Container allows privilege escalation',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /allowPrivilegeEscalation:\s*true/i
    ],
    message: 'Container allows privilege escalation. A process can gain more privileges than its parent.',
    remediation: 'Set securityContext.allowPrivilegeEscalation to false.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/'
    ]
  },
  {
    id: 'K8S-007',
    name: 'Read Only Root Filesystem Not Set',
    description: 'Container root filesystem is writable',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /containers:[\s\S]*?(?!.*readOnlyRootFilesystem:)/
    ],
    negativePatterns: [
      /readOnlyRootFilesystem:\s*true/i
    ],
    message: 'Container root filesystem is writable. Set readOnlyRootFilesystem to true.',
    remediation: 'Set securityContext.readOnlyRootFilesystem to true and use volumes for writable paths.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/'
    ]
  },
  {
    id: 'K8S-008',
    name: 'No Resource Limits',
    description: 'Container without resource limits',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /resources:/
    ],
    negativePatterns: [
      /limits:/,
      /requests:/
    ],
    message: 'Container does not have resource limits defined. This can lead to resource exhaustion.',
    remediation: 'Set resources.limits for CPU and memory to prevent resource abuse.',
    references: [
      'https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/'
    ]
  },

  // Capabilities Rules
  {
    id: 'K8S-009',
    name: 'Dangerous Capabilities Added',
    description: 'Container has dangerous Linux capabilities',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /add:[\s\S]*?-?\s*(ALL|NET_ADMIN|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|SYS_RAWIO|SYS_PACCT)/i
    ],
    message: 'Container has dangerous capabilities that can lead to container escape.',
    remediation: 'Drop ALL capabilities and only add specific required ones.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container'
    ]
  },
  {
    id: 'K8S-010',
    name: 'Capabilities Not Dropped',
    description: 'Container does not drop all capabilities',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /capabilities:[\s\S]*?add:/i
    ],
    negativePatterns: [
      /drop:[\s\S]*?ALL/i
    ],
    message: 'Container should drop ALL capabilities before adding specific ones.',
    remediation: 'Add capabilities.drop: ["ALL"] before adding specific capabilities.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container'
    ]
  },

  // Secrets Rules
  {
    id: 'K8S-011',
    name: 'Secret in Environment Variable',
    description: 'Secret value stored in environment variable',
    severity: 'high' as SeverityLevel,
    category: 'secrets-management' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /env:[\s\S]*?-?\s*name:\s*\w*(PASSWORD|SECRET|TOKEN|KEY|API_KEY)\w*\s*\n\s*value:/i
    ],
    message: 'Secret value directly set in environment variable. Secrets should use Secret resources.',
    remediation: 'Use Kubernetes Secrets with env.valueFrom.secretKeyRef instead of hardcoded values.',
    references: [
      'https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables'
    ]
  },
  {
    id: 'K8S-012',
    name: 'Secret Not Mounted as Volume',
    description: 'Secret should be mounted as read-only volume',
    severity: 'low' as SeverityLevel,
    category: 'secrets-management' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /envFrom:[\s\S]*?secretRef:/i
    ],
    negativePatterns: [
      /volumes:[\s\S]*?secret:/i
    ],
    message: 'Consider mounting secrets as volumes instead of environment variables for better security.',
    remediation: 'Mount secrets as read-only volumes to avoid exposing in environment.',
    references: [
      'https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod'
    ]
  },

  // Service Account Rules
  {
    id: 'K8S-013',
    name: 'Default Service Account Used',
    description: 'Pod uses default service account',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /kind:\s*Pod/
    ],
    negativePatterns: [
      /serviceAccountName:/
    ],
    message: 'Pod uses default service account. Create dedicated service accounts with minimal permissions.',
    remediation: 'Create a dedicated service account with specific RBAC permissions.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/'
    ]
  },
  {
    id: 'K8S-014',
    name: 'Automount Service Account Token',
    description: 'Service account token automatically mounted',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /automountServiceAccountToken:\s*true/i
    ],
    message: 'Service account token is automatically mounted. Disable if not needed.',
    remediation: 'Set automountServiceAccountToken to false if pod does not need API access.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server'
    ]
  },

  // Image Rules
  {
    id: 'K8S-015',
    name: 'Latest Image Tag',
    description: 'Container image uses "latest" tag',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A06:2021-Vulnerable and Outdated Components' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /image:\s*[^\s]*:latest/i,
      /image:\s*[^\s:]*$/m
    ],
    message: 'Using "latest" tag can lead to unpredictable deployments and security issues.',
    remediation: 'Use specific version tags (e.g., nginx:1.21.6-alpine).',
    references: [
      'https://kubernetes.io/docs/concepts/configuration/overview/#container-images'
    ]
  },
  {
    id: 'K8S-016',
    name: 'Image Pull Policy Not Always',
    description: 'Image pull policy not set to Always',
    severity: 'low' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /image:\s*[^\s]+:latest/
    ],
    negativePatterns: [
      /imagePullPolicy:\s*Always/i
    ],
    message: 'Image pull policy not set to Always. Latest tag may not pull newest image.',
    remediation: 'Set imagePullPolicy: Always when using latest tag or mutable tags.',
    references: [
      'https://kubernetes.io/docs/concepts/configuration/overview/#container-image-pull-policy'
    ]
  },

  // Network Policy Rules
  {
    id: 'K8S-017',
    name: 'No Network Policy',
    description: 'Namespace may not have network policies',
    severity: 'medium' as SeverityLevel,
    category: 'network-security' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|ReplicaSet)/i
    ],
    negativePatterns: [
      /kind:\s*NetworkPolicy/i
    ],
    message: 'Consider applying NetworkPolicy to control pod-to-pod traffic.',
    remediation: 'Create NetworkPolicy resources to restrict ingress and egress traffic.',
    references: [
      'https://kubernetes.io/docs/concepts/services-networking/network-policies/'
    ]
  },

  // Security Context Rules
  {
    id: 'K8S-018',
    name: 'No Security Context',
    description: 'Pod/Container lacks security context',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /containers:[\s\S]*?-?\s*name:/i
    ],
    negativePatterns: [
      /securityContext:/i
    ],
    message: 'No security context defined for container. Add security hardening settings.',
    remediation: 'Add securityContext with runAsNonRoot, readOnlyRootFilesystem, and other settings.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/'
    ]
  },
  {
    id: 'K8S-019',
    name: 'Seccomp Not Enabled',
    description: 'Seccomp profile not specified',
    severity: 'low' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /securityContext:/i
    ],
    negativePatterns: [
      /seccompProfile:/i
    ],
    message: 'Seccomp profile not specified. Consider using RuntimeDefault or custom profile.',
    remediation: 'Add seccompProfile with type: RuntimeDefault to restrict syscalls.',
    references: [
      'https://kubernetes.io/docs/tutorials/security/seccomp/'
    ]
  },
  {
    id: 'K8S-020',
    name: 'AppArmor Not Enabled',
    description: 'AppArmor profile not specified',
    severity: 'low' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /containers:/i
    ],
    negativePatterns: [
      /container\.apparmor\.security\.beta\.kubernetes.io/i
    ],
    message: 'AppArmor profile not specified. Consider using AppArmor for additional security.',
    remediation: 'Add container.apparmor.security.beta.kubernetes.io annotation with runtime/default.',
    references: [
      'https://kubernetes.io/docs/tutorials/security/apparmor/'
    ]
  },

  // Liveness/Readiness Probe Rules
  {
    id: 'K8S-021',
    name: 'No Health Checks',
    description: 'Container does not have liveness or readiness probes',
    severity: 'low' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A09:2021-Security Logging and Monitoring Failures' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /containers:/i
    ],
    negativePatterns: [
      /livenessProbe:/i,
      /readinessProbe:/i
    ],
    message: 'Container does not have health check probes defined.',
    remediation: 'Add livenessProbe and readinessProbe for proper health monitoring.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/'
    ]
  },

  // Volume Mount Rules
  {
    id: 'K8S-022',
    name: 'Sensitive Host Path Mounted',
    description: 'Sensitive host path mounted into container',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /hostPath:[\s\S]*?path:\s*["']?\/etc["']?/i,
      /hostPath:[\s\S]*?path:\s*["']?\/root["']?/i,
      /hostPath:[\s\S]*?path:\s*["']?\/var\/run\/docker\.sock["']?/i,
      /hostPath:[\s\S]*?path:\s*["']?\/["']?\s*$/m
    ],
    message: 'Sensitive host path mounted. This can lead to container escape or information disclosure.',
    remediation: 'Avoid mounting sensitive host paths. Use persistent volumes or emptyDir instead.',
    references: [
      'https://kubernetes.io/docs/concepts/storage/volumes/#hostpath'
    ]
  },
  {
    id: 'K8S-023',
    name: 'Docker Socket Mounted',
    description: 'Docker socket mounted into container',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /docker\.sock/i,
      /\/var\/run\/docker\.sock/i
    ],
    message: 'Docker socket mounted. This grants full Docker access and can lead to host compromise.',
    remediation: 'Avoid mounting Docker socket. Use Kubernetes API or dedicated container runtime.',
    references: [
      'https://kubernetes.io/docs/concepts/storage/volumes/#hostpath'
    ]
  },
  {
    id: 'K8S-024',
    name: 'Writeable Host Path',
    description: 'Host path mounted as writable',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /volumeMounts:[\s\S]*?hostPath/i
    ],
    negativePatterns: [
      /readOnly:\s*true/i
    ],
    message: 'Host path is mounted without readOnly: true. This allows modification of host filesystem.',
    remediation: 'Set readOnly: true for all hostPath volume mounts.',
    references: [
      'https://kubernetes.io/docs/concepts/storage/volumes/#hostpath'
    ]
  },

  // RBAC Rules
  {
    id: 'K8S-025',
    name: 'Wildcard RBAC Permissions',
    description: 'RBAC role grants wildcard permissions',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A01:2021-Broken Access Control' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /rules:[\s\S]*?-?\s*verbs:\s*\[?\s*["']?\*["']?/i,
      /rules:[\s\S]*?-?\s*resources:\s*\[?\s*["']?\*["']?/i,
      /rules:[\s\S]*?-?\s*apiGroups:\s*\[?\s*["']?\*["']?/i
    ],
    message: 'RBAC rule grants wildcard permissions. This violates least privilege.',
    remediation: 'Specify exact resources, verbs, and apiGroups instead of wildcards.',
    references: [
      'https://kubernetes.io/docs/reference/access-authn-authz/rbac/'
    ]
  },
  {
    id: 'K8S-026',
    name: 'Cluster Admin Role Binding',
    description: 'Service account bound to cluster-admin role',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A01:2021-Broken Access Control' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /roleRef:[\s\S]*?name:\s*["']?cluster-admin["']?/i,
      /cluster-role:\s*["']?cluster-admin["']?/i
    ],
    message: 'Service account has cluster-admin privileges. This is excessive for most workloads.',
    remediation: 'Create custom roles with specific permissions needed for the workload.',
    references: [
      'https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles'
    ]
  },
  {
    id: 'K8S-027',
    name: 'Secrets in RBAC',
    description: 'Role has access to secrets',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /resources:[\s\S]*?-?\s*["']?secrets["']?/i
    ],
    message: 'Role has access to secrets. Ensure this is necessary and scoped appropriately.',
    remediation: 'Limit secret access to specific namespaces and resources if possible.',
    references: [
      'https://kubernetes.io/docs/concepts/security/secrets-good-practices/'
    ]
  },

  // Pod Security Standards
  {
    id: 'K8S-028',
    name: 'No Pod Security Context',
    description: 'Pod-level security context not defined',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /spec:/i
    ],
    negativePatterns: [
      /spec:[\s\S]*?securityContext:/i
    ],
    message: 'Pod-level securityContext not defined. Set security defaults at pod level.',
    remediation: 'Add pod-level securityContext with fsGroup, runAsNonRoot, and seccompProfile.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod'
    ]
  },
  {
    id: 'K8S-029',
    name: 'fsGroup Not Set',
    description: 'Pod security context lacks fsGroup',
    severity: 'low' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /spec:[\s\S]*?securityContext:/i
    ],
    negativePatterns: [
      /fsGroup:/i
    ],
    message: 'fsGroup not set in pod security context. Volumes may have incorrect permissions.',
    remediation: 'Set fsGroup to ensure volumes are accessible by the container.',
    references: [
      'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod'
    ]
  },

  // TLS Rules
  {
    id: 'K8S-030',
    name: 'Ingress Without TLS',
    description: 'Ingress resource does not have TLS configured',
    severity: 'high' as SeverityLevel,
    category: 'network-security' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['yaml', 'yml'],
    patterns: [
      /kind:\s*Ingress/i
    ],
    negativePatterns: [
      /tls:/i
    ],
    message: 'Ingress does not have TLS configured. Traffic will be unencrypted.',
    remediation: 'Add TLS configuration with secretName to ingress spec.',
    references: [
      'https://kubernetes.io/docs/concepts/services-networking/ingress/#tls'
    ]
  }
];
