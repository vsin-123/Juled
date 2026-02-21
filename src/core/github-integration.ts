import * as core from '@actions/core';
import * as github from '@actions/github';
import { GitHubPRContext, PRFile, SecurityFinding, ScanResult, SeverityLevel } from '../types';

export class GitHubIntegration {
  private octokit: ReturnType<typeof github.getOctokit>;
  private context: GitHubPRContext | null = null;

  constructor(token: string) {
    this.octokit = github.getOctokit(token);
  }

  public async initialize(): Promise<boolean> {
    try {
      const { payload, repo } = github.context;

      if (!payload.pull_request) {
        core.info('Not running in a pull request context');
        return false;
      }

      const pr = payload.pull_request;

      // Get changed files
      const { data: files } = await this.octokit.rest.pulls.listFiles({
        owner: repo.owner,
        repo: repo.repo,
        pull_number: pr.number
      });

      this.context = {
        owner: repo.owner,
        repo: repo.repo,
        pullNumber: pr.number,
        sha: pr.head.sha,
        baseSha: pr.base.sha,
        headSha: pr.head.sha,
        files: files.map(f => ({
          filename: f.filename,
          status: f.status as PRFile['status'],
          additions: f.additions,
          deletions: f.deletions,
          patch: f.patch,
          previousFilename: f.previous_filename
        }))
      };

      return true;
    } catch (error) {
      core.error(`Failed to initialize GitHub context: ${error}`);
      return false;
    }
  }

  public getChangedFiles(): PRFile[] {
    return this.context?.files || [];
  }

  public async postPRComment(summary: string, findings: SecurityFinding[]): Promise<void> {
    if (!this.context) {
      core.warning('GitHub context not initialized');
      return;
    }

    try {
      // Build comment body
      const body = this.buildPRComment(summary, findings);

      // Check for existing comment
      const { data: comments } = await this.octokit.rest.issues.listComments({
        owner: this.context.owner,
        repo: this.context.repo,
        issue_number: this.context.pullNumber
      });

      const existingComment = comments.find(c =>
        c.body?.includes('🔒 PR Security Scanner Results')
      );

      if (existingComment) {
        // Update existing comment
        await this.octokit.rest.issues.updateComment({
          owner: this.context.owner,
          repo: this.context.repo,
          comment_id: existingComment.id,
          body
        });
        core.info('Updated existing PR comment');
      } else {
        // Create new comment
        await this.octokit.rest.issues.createComment({
          owner: this.context.owner,
          repo: this.context.repo,
          issue_number: this.context.pullNumber,
          body
        });
        core.info('Created new PR comment');
      }
    } catch (error) {
      core.error(`Failed to post PR comment: ${error}`);
    }
  }

  public async createCheckRun(results: ScanResult[]): Promise<void> {
    if (!this.context) {
      core.warning('GitHub context not initialized');
      return;
    }

    try {
      const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
      const criticalFindings = results.reduce(
        (sum, r) => sum + r.findings.filter(f => f.severity === 'critical').length, 0
      );
      const highFindings = results.reduce(
        (sum, r) => sum + r.findings.filter(f => f.severity === 'high').length, 0
      );

      const conclusion = criticalFindings > 0 ? 'failure' : 'success';

      // Build annotations for findings
      const annotations = results.flatMap(result =>
        result.findings.map(finding => ({
          path: finding.filePath,
          start_line: finding.lineNumber,
          end_line: finding.lineNumber,
          annotation_level: this.severityToAnnotationLevel(finding.severity),
          message: finding.message,
          title: finding.ruleId,
          raw_details: finding.description
        }))
      ).slice(0, 50); // GitHub has a limit of 50 annotations per request

      await this.octokit.rest.checks.create({
        owner: this.context.owner,
        repo: this.context.repo,
        name: 'PR Security Scanner',
        head_sha: this.context.sha,
        status: 'completed',
        conclusion,
        output: {
          title: 'Security Scan Results',
          summary: `Found ${totalFindings} security issues`,
          annotations
        }
      });

      core.info(`Created check run with conclusion: ${conclusion}`);
    } catch (error) {
      core.error(`Failed to create check run: ${error}`);
    }
  }

  public async postAnnotations(results: ScanResult[]): Promise<void> {
    if (!this.context) {
      core.warning('GitHub context not initialized');
      return;
    }

    try {
      // Group findings by file
      const findingsByFile = new Map<string, SecurityFinding[]>();
      for (const result of results) {
        if (result.findings.length > 0) {
          const existing = findingsByFile.get(result.filePath) || [];
          findingsByFile.set(result.filePath, [...existing, ...result.findings]);
        }
      }

      // Post review comments for each finding
      for (const [filePath, findings] of findingsByFile) {
        for (const finding of findings) {
          // Only post comments for critical and high severity
          if (finding.severity !== 'critical' && finding.severity !== 'high') {
            continue;
          }

          try {
            await this.octokit.rest.pulls.createReviewComment({
              owner: this.context.owner,
              repo: this.context.repo,
              pull_number: this.context.pullNumber,
              commit_id: this.context.sha,
              path: filePath,
              line: finding.lineNumber,
              side: 'RIGHT',
              body: this.buildReviewComment(finding)
            });
          } catch (error) {
            // Line might not be in the diff, skip
            core.debug(`Could not post comment for ${filePath}:${finding.lineNumber}: ${error}`);
          }
        }
      }
    } catch (error) {
      core.error(`Failed to post annotations: ${error}`);
    }
  }

  public setOutputs(findings: SecurityFinding[]): void {
    const counts = {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length
    };

    core.setOutput('findings-count', counts.total);
    core.setOutput('critical-count', counts.critical);
    core.setOutput('high-count', counts.high);
    core.setOutput('medium-count', counts.medium);
    core.setOutput('low-count', counts.low);
  }

  public shouldFail(failOn: SeverityLevel, findings: SecurityFinding[]): boolean {
    const severityOrder: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info'];
    const failIndex = severityOrder.indexOf(failOn);

    if (failIndex === -1) return false;

    for (const finding of findings) {
      const findingIndex = severityOrder.indexOf(finding.severity);
      if (findingIndex <= failIndex) {
        return true;
      }
    }

    return false;
  }

  private buildPRComment(summary: string, findings: SecurityFinding[]): string {
    const lines: string[] = [
      '## 🔒 PR Security Scanner Results',
      '',
      '```',
      summary,
      '```',
      ''
    ];

    if (findings.length === 0) {
      lines.push('✅ No security issues found in the changed files!');
    } else {
      lines.push('### 🚨 Critical and High Severity Findings');
      lines.push('');

      const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');

      if (criticalFindings.length === 0) {
        lines.push('No critical or high severity issues found.');
      } else {
        for (const finding of criticalFindings.slice(0, 10)) {
          const emoji = finding.severity === 'critical' ? '🚨' : '⚠️';
          lines.push(`${emoji} **${finding.ruleId}** in \`${finding.filePath}:${finding.lineNumber}\``);
          lines.push(`   ${finding.message}`);
          lines.push('');
        }

        if (criticalFindings.length > 10) {
          lines.push(`*... and ${criticalFindings.length - 10} more critical/high findings*`, '');
        }
      }

      // Add link to full report
      lines.push('');
      lines.push('📄 **Full report available in the Actions artifacts**');
    }

    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('🛡️ This scan was performed by the PR Security Scanner');
    lines.push('');
    lines.push('<details>');
    lines.push('<summary>📋 Scan Configuration</summary>');
    lines.push('');
    lines.push('The scanner checks for:');
    lines.push('- SQL Injection vulnerabilities');
    lines.push('- Hardcoded secrets and credentials');
    lines.push('- Insecure configuration');
    lines.push('- Dependency vulnerabilities');
    lines.push('- Container security issues');
    lines.push('- Infrastructure misconfigurations');
    lines.push('- OWASP Top 10 vulnerabilities');
    lines.push('</details>');

    return lines.join('\n');
  }

  private buildReviewComment(finding: SecurityFinding): string {
    const lines: string[] = [
      `🔒 **${finding.ruleId}** - ${finding.severity.toUpperCase()}`,
      '',
      finding.message,
      '',
      finding.description
    ];

    if (finding.remediation) {
      lines.push('', '**Remediation:**', finding.remediation);
    }

    return lines.join('\n');
  }

  private severityToAnnotationLevel(severity: SeverityLevel): 'notice' | 'warning' | 'failure' {
    switch (severity) {
      case 'critical':
        return 'failure';
      case 'high':
      case 'medium':
        return 'warning';
      case 'low':
      case 'info':
      default:
        return 'notice';
    }
  }
}
