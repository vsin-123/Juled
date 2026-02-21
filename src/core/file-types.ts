import { FileType } from '../types';

export const FILE_TYPE_DEFINITIONS: FileType[] = [
  // Database Files
  {
    name: 'sql',
    extensions: ['.sql'],
    category: 'database',
    scanner: 'sql-scanner',
    mimeTypes: ['application/sql', 'text/x-sql']
  },
  {
    name: 'mongodb',
    extensions: ['.mongo', '.mongodb'],
    category: 'database',
    scanner: 'sql-scanner'
  },
  {
    name: 'redis',
    extensions: ['.redis'],
    category: 'database',
    scanner: 'sql-scanner'
  },
  {
    name: 'cassandra',
    extensions: ['.cql'],
    category: 'database',
    scanner: 'sql-scanner'
  },

  // Configuration Files
  {
    name: 'json',
    extensions: ['.json', '.jsonc'],
    filenames: ['package.json', 'tsconfig.json', 'package-lock.json'],
    category: 'configuration',
    scanner: 'config-scanner',
    mimeTypes: ['application/json']
  },
  {
    name: 'yaml',
    extensions: ['.yml', '.yaml'],
    filenames: ['.github/workflows/*.yml', 'docker-compose.yml', 'kubernetes.yml'],
    category: 'configuration',
    scanner: 'config-scanner',
    mimeTypes: ['application/x-yaml', 'text/yaml']
  },
  {
    name: 'xml',
    extensions: ['.xml', '.xsd', '.xslt', '.wsdl'],
    filenames: ['pom.xml', 'web.xml', 'androidmanifest.xml'],
    category: 'configuration',
    scanner: 'config-scanner',
    mimeTypes: ['application/xml', 'text/xml']
  },
  {
    name: 'ini',
    extensions: ['.ini', '.cfg', '.conf', '.config'],
    category: 'configuration',
    scanner: 'config-scanner'
  },
  {
    name: 'properties',
    extensions: ['.properties'],
    filenames: ['.env', '.env.local', '.env.production', '.env.development'],
    category: 'configuration',
    scanner: 'config-scanner'
  },
  {
    name: 'toml',
    extensions: ['.toml'],
    filenames: ['pyproject.toml', 'Cargo.toml', 'config.toml'],
    category: 'configuration',
    scanner: 'config-scanner'
  },
  {
    name: 'ini-config',
    extensions: ['.cnf', '.prefs'],
    category: 'configuration',
    scanner: 'config-scanner'
  },

  // Markup Files
  {
    name: 'html',
    extensions: ['.html', '.htm', '.xhtml'],
    category: 'markup',
    scanner: 'markup-scanner',
    mimeTypes: ['text/html']
  },
  {
    name: 'markdown',
    extensions: ['.md', '.markdown', '.mdx'],
    category: 'documentation',
    scanner: 'markup-scanner'
  },

  // Data Files
  {
    name: 'csv',
    extensions: ['.csv', '.tsv'],
    category: 'data',
    scanner: 'data-scanner',
    mimeTypes: ['text/csv']
  },
  {
    name: 'jsonl',
    extensions: ['.jsonl', '.ndjson'],
    category: 'data',
    scanner: 'data-scanner'
  },

  // Container & Orchestration
  {
    name: 'dockerfile',
    extensions: ['.dockerfile'],
    filenames: ['Dockerfile', 'Dockerfile.*', 'dockerfile'],
    category: 'container',
    scanner: 'infrastructure-scanner'
  },
  {
    name: 'docker-compose',
    extensions: ['.yml', '.yaml'],
    filenames: ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'],
    category: 'container',
    scanner: 'infrastructure-scanner'
  },
  {
    name: 'kubernetes',
    extensions: ['.yml', '.yaml'],
    filenames: ['deployment.yml', 'service.yml', 'ingress.yml', 'pod.yml', 'configmap.yml'],
    category: 'container',
    scanner: 'infrastructure-scanner'
  },
  {
    name: 'helm',
    extensions: ['.yaml', '.yml'],
    filenames: ['Chart.yaml', 'values.yaml'],
    category: 'container',
    scanner: 'infrastructure-scanner'
  },

  // Infrastructure as Code
  {
    name: 'terraform',
    extensions: ['.tf', '.tfvars', '.hcl'],
    filenames: ['main.tf', 'variables.tf', 'outputs.tf', 'terraform.tfvars'],
    category: 'infrastructure',
    scanner: 'infrastructure-scanner'
  },
  {
    name: 'cloudformation',
    extensions: ['.json', '.yaml', '.yml', '.template'],
    filenames: ['template.yaml', 'template.json', 'cloudformation.yaml'],
    category: 'infrastructure',
    scanner: 'infrastructure-scanner'
  },
  {
    name: 'ansible',
    extensions: ['.yml', '.yaml'],
    filenames: ['playbook.yml', 'site.yml', 'requirements.yml'],
    category: 'infrastructure',
    scanner: 'infrastructure-scanner'
  },
  {
    name: 'pulumi',
    extensions: ['.ts', '.js', '.py', '.go', '.cs'],
    filenames: ['Pulumi.yaml', 'Pulumi.yml'],
    category: 'infrastructure',
    scanner: 'infrastructure-scanner'
  },
  {
    name: 'vagrant',
    extensions: ['.rb'],
    filenames: ['Vagrantfile'],
    category: 'infrastructure',
    scanner: 'infrastructure-scanner'
  },

  // Build Files
  {
    name: 'maven',
    extensions: ['.xml'],
    filenames: ['pom.xml'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'gradle',
    extensions: ['.gradle', '.kts'],
    filenames: ['build.gradle', 'settings.gradle', 'gradle.properties', 'build.gradle.kts'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'npm',
    extensions: ['.json'],
    filenames: ['package.json', 'package-lock.json'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'yarn',
    extensions: ['.lock'],
    filenames: ['yarn.lock', '.yarnrc', '.yarnrc.yml'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'pip',
    extensions: ['.txt', '.in'],
    filenames: ['requirements.txt', 'requirements-dev.txt', 'requirements-base.txt'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'pipenv',
    extensions: ['.lock', '.toml'],
    filenames: ['Pipfile', 'Pipfile.lock'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'poetry',
    extensions: ['.toml', '.lock'],
    filenames: ['pyproject.toml', 'poetry.lock'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'gemfile',
    extensions: ['.lock'],
    filenames: ['Gemfile', 'Gemfile.lock'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'go-mod',
    extensions: ['.mod', '.sum'],
    filenames: ['go.mod', 'go.sum'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'composer',
    extensions: ['.json', '.lock'],
    filenames: ['composer.json', 'composer.lock'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'cargo',
    extensions: ['.toml', '.lock'],
    filenames: ['Cargo.toml', 'Cargo.lock'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'nuget',
    extensions: ['.config'],
    filenames: ['packages.config', 'nuget.config'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'makefile',
    extensions: ['.mk'],
    filenames: ['Makefile', 'makefile', 'GNUmakefile'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'cmake',
    extensions: ['.txt', '.cmake'],
    filenames: ['CMakeLists.txt'],
    category: 'build',
    scanner: 'build-scanner'
  },
  {
    name: 'bazel',
    extensions: ['.bazel', '.bzl', '.bazelrc'],
    filenames: ['BUILD', 'WORKSPACE'],
    category: 'build',
    scanner: 'build-scanner'
  },

  // Source Code Files (for completeness)
  {
    name: 'javascript',
    extensions: ['.js', '.jsx', '.mjs', '.cjs'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'typescript',
    extensions: ['.ts', '.tsx'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'python',
    extensions: ['.py', '.pyw', '.pyi'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'java',
    extensions: ['.java'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'go',
    extensions: ['.go'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'ruby',
    extensions: ['.rb', '.rbw', '.rake', '.gemspec'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'php',
    extensions: ['.php', '.phtml', '.php3', '.php4', '.php5'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'csharp',
    extensions: ['.cs', '.csx'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'cpp',
    extensions: ['.cpp', '.cxx', '.cc', '.c', '.h', '.hpp'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'rust',
    extensions: ['.rs'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'swift',
    extensions: ['.swift'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'kotlin',
    extensions: ['.kt', '.kts'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'scala',
    extensions: ['.scala', '.sc'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'shell',
    extensions: ['.sh', '.bash', '.zsh', '.ksh'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'powershell',
    extensions: ['.ps1', '.psm1', '.psd1'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'perl',
    extensions: ['.pl', '.pm', '.perl'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'lua',
    extensions: ['.lua'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'r',
    extensions: ['.r', '.R'],
    category: 'source-code',
    scanner: 'source-scanner'
  },
  {
    name: 'matlab',
    extensions: ['.m', '.mlx'],
    category: 'source-code',
    scanner: 'source-scanner'
  }
];

export const EXTENSION_TO_TYPE_MAP: Map<string, string> = new Map();
export const FILENAME_TO_TYPE_MAP: Map<string, string> = new Map();

FILE_TYPE_DEFINITIONS.forEach(fileType => {
  fileType.extensions.forEach(ext => {
    EXTENSION_TO_TYPE_MAP.set(ext, fileType.name);
  });
  if (fileType.filenames) {
    fileType.filenames.forEach(filename => {
      FILENAME_TO_TYPE_MAP.set(filename.toLowerCase(), fileType.name);
    });
  }
});
