import { SecurityRule, SecurityCategory, OwaspCategory, SeverityLevel } from '../../types';

export const TERRAFORM_SECURITY_RULES: SecurityRule[] = [
  // Security Group Rules
  {
    id: 'TF-001',
    name: 'Overly Permissive Security Group',
    description: 'Security group allows unrestricted inbound access',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\]/i,
      /0\.0\.0\.0\/0.*ingress/i,
      /ingress.*0\.0\.0\.0\/0/i,
      /from_port\s*=\s*22.*0\.0\.0\.0\/0/i,
      /from_port\s*=\s*3389.*0\.0\.0\.0\/0/i,
      /from_port\s*=\s*3306.*0\.0\.0\.0\/0/i,
      /from_port\s*=\s*5432.*0\.0\.0\.0\/0/i
    ],
    message: 'Security group allows unrestricted access from the internet (0.0.0.0/0).',
    remediation: 'Restrict CIDR blocks to specific IP ranges. Avoid using 0.0.0.0/0 for sensitive ports.',
    references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
      'https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group'
    ]
  },
  {
    id: 'TF-002',
    name: 'Security Group All Ports Open',
    description: 'Security group allows all ports (0-65535)',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /from_port\s*=\s*0\s+to_port\s*=\s*65535/,
      /from_port\s*=\s*["']all["']/i
    ],
    message: 'Security group allows traffic on all ports. This is overly permissive.',
    remediation: 'Specify only the required ports for your application.',
    references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html'
    ]
  },

  // S3 Bucket Rules
  {
    id: 'TF-003',
    name: 'S3 Bucket Public Access',
    description: 'S3 bucket allows public access',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /acl\s*=\s*["']public-read["']/i,
      /acl\s*=\s*["']public-read-write["']/i,
      /acl\s*=\s*["']authenticated-read["']/i,
      /Principal\s*=\s*["']\*["']/,
      /Action\s*=\s*["']s3:\*["']/
    ],
    message: 'S3 bucket is configured with public access. This exposes data to the internet.',
    remediation: 'Set acl to "private" and use proper IAM policies for access control.',
    references: [
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html',
      'https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block'
    ]
  },
  {
    id: 'TF-004',
    name: 'S3 Bucket Without Encryption',
    description: 'S3 bucket does not have encryption enabled',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /resource\s+"aws_s3_bucket".*\{(?!.*server_side_encryption_configuration)/s
    ],
    message: 'S3 bucket may not have encryption enabled. Data should be encrypted at rest.',
    remediation: 'Enable server-side encryption using AES256 or aws:kms.',
    references: [
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html'
    ]
  },
  {
    id: 'TF-005',
    name: 'S3 Bucket Without Versioning',
    description: 'S3 bucket versioning is not enabled',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /resource\s+"aws_s3_bucket".*\{(?!.*versioning)/s
    ],
    message: 'S3 bucket versioning is not enabled. This limits recovery options.',
    remediation: 'Enable versioning to protect against accidental deletion and enable recovery.',
    references: [
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html'
    ]
  },
  {
    id: 'TF-006',
    name: 'S3 Bucket Without Logging',
    description: 'S3 bucket access logging is not enabled',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A09:2021-Security Logging and Monitoring Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /resource\s+"aws_s3_bucket".*\{(?!.*logging)/s
    ],
    message: 'S3 bucket access logging is not enabled.',
    remediation: 'Enable access logging to monitor bucket access and detect security issues.',
    references: [
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html'
    ]
  },

  // RDS/Database Rules
  {
    id: 'TF-007',
    name: 'RDS Publicly Accessible',
    description: 'RDS instance is publicly accessible',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /publicly_accessible\s*=\s*true/i
    ],
    message: 'RDS database is publicly accessible from the internet.',
    remediation: 'Set publicly_accessible to false and use VPC peering or VPN for access.',
    references: [
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html'
    ]
  },
  {
    id: 'TF-008',
    name: 'RDS Without Encryption',
    description: 'RDS instance does not have encryption enabled',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /resource\s+"aws_db_instance".*\{(?!.*storage_encrypted)/s
    ],
    message: 'RDS instance storage encryption is not enabled.',
    remediation: 'Enable storage_encrypted for all RDS instances.',
    references: [
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html'
    ]
  },
  {
    id: 'TF-009',
    name: 'RDS No Backup Retention',
    description: 'RDS backup retention period not set or too low',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /backup_retention_period\s*=\s*0/,
      /backup_retention_period\s*=\s*[12]\s*$/m
    ],
    message: 'RDS backup retention period is set to 0 or very low.',
    remediation: 'Set backup_retention_period to at least 7 days for production databases.',
    references: [
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html'
    ]
  },

  // EC2 Rules
  {
    id: 'TF-010',
    name: 'EC2 IMDSv1 Enabled',
    description: 'EC2 instance allows IMDSv1 (vulnerable to SSRF)',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A10:2021-Server-Side Request Forgery (SSRF)' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /http_tokens\s*=\s*["']optional["']/i
    ],
    message: 'EC2 instance allows IMDSv1 which is vulnerable to SSRF attacks.',
    remediation: 'Set http_tokens to "required" to enforce IMDSv2.',
    references: [
      'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html'
    ]
  },
  {
    id: 'TF-011',
    name: 'EC2 Unencrypted EBS',
    description: 'EBS volumes are not encrypted',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /resource\s+"aws_ebs_volume".*\{(?!.*encrypted\s*=\s*true)/s
    ],
    message: 'EBS volume is not encrypted.',
    remediation: 'Enable encryption for all EBS volumes.',
    references: [
      'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html'
    ]
  },

  // IAM Rules
  {
    id: 'TF-012',
    name: 'IAM Password Policy Weak',
    description: 'IAM password policy does not enforce strong passwords',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /minimum_password_length\s*=\s*[0-7]/,
      /require_lowercase_characters\s*=\s*false/i,
      /require_uppercase_characters\s*=\s*false/i,
      /require_numbers\s*=\s*false/i,
      /require_symbols\s*=\s*false/i
    ],
    message: 'IAM password policy is weak and does not enforce strong password requirements.',
    remediation: 'Enforce strong password policies: minimum 14 characters with mixed case, numbers, and symbols.',
    references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html'
    ]
  },
  {
    id: 'TF-013',
    name: 'IAM Wildcard Permissions',
    description: 'IAM policy grants overly permissive wildcard access',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /Action\s*=\s*["']\*["']/,
      /Resource\s*=\s*["']\*["']/,
      /Effect\s*=\s*["']Allow["'].*Action.*\*/s
    ],
    message: 'IAM policy grants wildcard (*) permissions. This violates least privilege.',
    remediation: 'Specify exact actions and resources needed. Avoid using wildcards.',
    references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege'
    ]
  },
  {
    id: 'TF-014',
    name: 'IAM Access Key Not Rotated',
    description: 'IAM access keys without rotation requirement',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /aws_iam_access_key/
    ],
    message: 'IAM access key created without rotation policy.',
    remediation: 'Implement key rotation every 90 days and use IAM roles where possible.',
    references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html'
    ]
  },

  // Lambda Rules
  {
    id: 'TF-015',
    name: 'Lambda Environment Variables Exposed',
    description: 'Lambda function may expose sensitive environment variables',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /environment\s*\{[\s\S]*?variables\s*=\s*\{/,
      /PASSWORD|SECRET|TOKEN|KEY/i
    ],
    message: 'Sensitive data may be stored in Lambda environment variables.',
    remediation: 'Use AWS Secrets Manager or Parameter Store for sensitive values.',
    references: [
      'https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html'
    ]
  },

  // CloudTrail Rules
  {
    id: 'TF-016',
    name: 'CloudTrail Not Enabled',
    description: 'AWS CloudTrail logging is not enabled',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A09:2021-Security Logging and Monitoring Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /resource\s+"aws_cloudtrail"/,
      /is_multi_region_trail\s*=\s*false/
    ],
    message: 'CloudTrail may not be enabled or configured for multi-region.',
    remediation: 'Enable CloudTrail for all regions and ensure logs are encrypted and have log file validation.',
    references: [
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html'
    ]
  },
  {
    id: 'TF-017',
    name: 'CloudTrail Without Encryption',
    description: 'CloudTrail S3 bucket without encryption',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /kms_key_id\s*=\s*null/i,
      /enable_log_file_validation\s*=\s*false/i
    ],
    message: 'CloudTrail log encryption or validation is not enabled.',
    remediation: 'Enable KMS encryption and log file validation for CloudTrail.',
    references: [
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html'
    ]
  },

  // KMS Rules
  {
    id: 'TF-018',
    name: 'KMS Key Rotation Disabled',
    description: 'KMS key automatic rotation is not enabled',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /enable_key_rotation\s*=\s*false/i
    ],
    message: 'KMS key automatic rotation is disabled.',
    remediation: 'Enable automatic key rotation for all KMS keys.',
    references: [
      'https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html'
    ]
  },

  // VPC Rules
  {
    id: 'TF-019',
    name: 'VPC Flow Logs Disabled',
    description: 'VPC flow logs are not enabled',
    severity: 'medium' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A09:2021-Security Logging and Monitoring Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /resource\s+"aws_vpc".*\{(?!.*aws_flow_log)/s
    ],
    message: 'VPC flow logs are not enabled.',
    remediation: 'Enable VPC flow logs for network traffic analysis and security monitoring.',
    references: [
      'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'
    ]
  },

  // ECR Rules
  {
    id: 'TF-020',
    name: 'ECR Repository Public',
    description: 'ECR repository is publicly accessible',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /scan_on_push\s*=\s*false/i
    ],
    message: 'ECR image scanning is not enabled on push.',
    remediation: 'Enable scan_on_push to detect vulnerabilities in container images.',
    references: [
      'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html'
    ]
  },

  // ElastiCache Rules
  {
    id: 'TF-021',
    name: 'ElastiCache Without Encryption',
    description: 'ElastiCache cluster does not have encryption enabled',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /at_rest_encryption_enabled\s*=\s*false/i,
      /transit_encryption_enabled\s*=\s*false/i
    ],
    message: 'ElastiCache encryption at rest or in transit is not enabled.',
    remediation: 'Enable both at_rest_encryption_enabled and transit_encryption_enabled.',
    references: [
      'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/WhatIs.html'
    ]
  },

  // Elasticsearch Rules
  {
    id: 'TF-022',
    name: 'Elasticsearch Domain Public',
    description: 'Elasticsearch domain is accessible from the internet',
    severity: 'critical' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A05:2021-Security Misconfiguration' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /aws_elasticsearch_domain.*\{(?!.*vpc_options)/s
    ],
    message: 'Elasticsearch domain is not configured within a VPC.',
    remediation: 'Deploy Elasticsearch within a VPC and use VPC endpoints for access.',
    references: [
      'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html'
    ]
  },
  {
    id: 'TF-023',
    name: 'Elasticsearch Without Encryption',
    description: 'Elasticsearch domain encryption not enabled',
    severity: 'high' as SeverityLevel,
    category: 'infrastructure' as SecurityCategory,
    owaspCategory: 'A02:2021-Cryptographic Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /encrypt_at_rest\s*\{[^}]*enabled\s*=\s*false/i
    ],
    message: 'Elasticsearch encryption at rest is disabled.',
    remediation: 'Enable encryption at rest for Elasticsearch domains.',
    references: [
      'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html'
    ]
  },

  // Secrets Manager
  {
    id: 'TF-024',
    name: 'Secrets Manager Without Rotation',
    description: 'Secrets Manager secret without automatic rotation',
    severity: 'medium' as SeverityLevel,
    category: 'secrets-management' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /aws_secretsmanager_secret.*\{(?!.*rotation_rules)/s
    ],
    message: 'Secrets Manager secret does not have automatic rotation configured.',
    remediation: 'Enable automatic rotation for secrets using rotation_rules.',
    references: [
      'https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html'
    ]
  },

  // Hardcoded Secrets in Terraform
  {
    id: 'TF-025',
    name: 'Hardcoded Password in Terraform',
    description: 'Password hardcoded in Terraform configuration',
    severity: 'critical' as SeverityLevel,
    category: 'hardcoded-secrets' as SecurityCategory,
    owaspCategory: 'A07:2021-Identification and Authentication Failures' as OwaspCategory,
    fileTypes: ['terraform', 'tf', 'hcl'],
    patterns: [
      /password\s*=\s*["'][^$\{][^"']{4,}["']/i,
      /master_password\s*=\s*["'][^$\{][^"']{4,}["']/i,
      /admin_password\s*=\s*["'][^$\{][^"']{4,}["']/i
    ],
    message: 'Password hardcoded in Terraform configuration.',
    remediation: 'Use variables with sensitive = true or Secrets Manager references.',
    references: [
      'https://www.terraform.io/docs/language/values/variables.html#suppressing-values-in-cli-output'
    ]
  }
];
