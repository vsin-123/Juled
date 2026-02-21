import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';
import { ScannerEngine } from './core/scanner-engine';
import { AIScannerEngine } from './scanners/ai-scanner';
import { GitHubIntegration } from './core/github-integration';
import { ScanOptions, SeverityLevel, ReportData } from './types';
import { AIManager } from './ai';

async function run(): Promise<void> {
  try {
    // Get inputs
    const token = core.getInput('github-token', { required: true });
    const scanDirectory = core.getInput('scan-directory') || '.';
    const failOn = (core.getInput('fail-on') || 'high') as SeverityLevel;
    const includeExtensions = core.getInput('include-extensions');
    const excludeExtensions = core.getInput('exclude-extensions');
    const excludePaths = core.getInput('exclude-paths');
    const enableOwasp = core.getBooleanInput('enable-owasp');
    const enableSecrets = core.getBooleanInput('enable-secrets');
    const outputFormat = core.getInput('output-format') || 'markdown';
    const verbose = core.getBooleanInput('verbose');

    // AI-related inputs
    const enableAiAnalysis = core.getBooleanInput('enable-ai-analysis');
    const aiProvider = core.getInput('ai-provider');
    const aiConfigPath = core.getInput('ai-config-path');
    const aiBatchSize = parseInt(core.getInput('ai-batch-size') || '5');
    const aiMaxConcurrency = parseInt(core.getInput('ai-max-concurrency') || '3');
    const aiCostLimit = parseFloat(core.getInput('ai-cost-limit') || '50');
    const aiCacheResults = core.getBooleanInput('ai-cache-results');

    if (verbose) {
      core.info('🔍 PR Security Scanner Starting...');
      core.info(`Scan directory: ${scanDirectory}`);
      core.info(`Fail on: ${failOn}`);
      core.info(`Output format: ${outputFormat}`);
      if (enableAiAnalysis) {
        core.info('🤖 AI Analysis Enabled');
        if (aiProvider) core.info(`AI Provider: ${aiProvider}`);
      }
    }

    // Validate scan directory
    const resolvedDir = path.resolve(scanDirectory);
    if (!fs.existsSync(resolvedDir)) {
      throw new Error(`Scan directory does not exist: ${resolvedDir}`);
    }

    // Parse extension filters
    const includeExts = includeExtensions ? includeExtensions.split(',').map(e => e.trim().toLowerCase()) : undefined;
    const excludeExts = excludeExtensions ? excludeExtensions.split(',').map(e => e.trim().toLowerCase()) : undefined;
    const excludePathsList = excludePaths ? excludePaths.split(',').map(p => p.trim()) : ['node_modules', 'dist', 'build', 'coverage', '.git'];

    // Initialize AI manager if AI analysis is enabled
    let aiManager: AIManager | undefined;
    if (enableAiAnalysis) {
      core.info('🤖 Initializing AI manager...');
      
      let aiSettings;
      if (aiConfigPath && fs.existsSync(aiConfigPath)) {
        core.info(`Loading AI config from: ${aiConfigPath}`);
        aiSettings = AIManager.loadSettings(aiConfigPath);
      }

      aiManager = new AIManager(aiSettings);
      
      // Initialize providers
      const providers = aiManager.getAllProviders();
      if (providers.length === 0) {
        core.warning('No AI providers configured. Please set up AI providers in configuration file.');
      } else {
        core.info(`Loaded ${providers.length} AI provider(s)`);
        
        // Validate providers
        for (const provider of providers) {
          try {
            await provider.initialize();
            const isValid = await provider.validateConfig();
            if (!isValid) {
              core.warning(`AI provider ${provider.name} validation failed`);
            } else {
              core.info(`✅ AI provider ${provider.name} ready`);
            }
          } catch (error) {
            core.warning(`Failed to initialize AI provider ${provider.name}: ${error}`);
          }
        }
      }
    }

    // Initialize scanner (use AI scanner if AI is enabled)
    const engine = enableAiAnalysis && aiManager 
      ? new AIScannerEngine(aiManager, { enableAI: true, costLimit: aiCostLimit })
      : new ScannerEngine();

    // Build scan options
    const options: ScanOptions = {
      directory: resolvedDir,
      includeExtensions: includeExts,
      excludeExtensions: excludeExts,
      excludePaths: excludePathsList,
      failOn,
      enableOwasp,
      enableSecrets,
      outputFormat: outputFormat as 'json' | 'sarif' | 'markdown',
      verbose,
      parallel: true,
      maxWorkers: 4,
      // AI options
      enableAiAnalysis,
      aiProvider,
      aiConfigPath,
      aiBatchSize,
      aiMaxConcurrency,
      aiCostLimit,
      aiCacheResults
    };

    // Run scan
    core.info('🚀 Starting security scan...');
    const report = await engine.scan(options);

    // Generate and save report
    const reportDir = path.join(process.env.GITHUB_WORKSPACE || '.', 'security-reports');
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    // Save reports in multiple formats
    const markdownReport = engine.generateMarkdownReport(report);
    const markdownPath = path.join(reportDir, 'security-report.md');
    fs.writeFileSync(markdownPath, markdownReport);
    core.info(`📄 Markdown report saved to: ${markdownPath}`);

    const jsonPath = path.join(reportDir, 'security-report.json');
    fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
    core.info(`📄 JSON report saved to: ${jsonPath}`);

    const sarifReport = engine.generateSARIFReport(report);
    const sarifPath = path.join(reportDir, 'security-report.sarif');
    fs.writeFileSync(sarifPath, sarifReport);
    core.info(`📄 SARIF report saved to: ${sarifPath}`);

    core.setOutput('report-path', markdownPath);

    // GitHub Integration
    const github = new GitHubIntegration(token);
    const isGitHubContext = await github.initialize();

    if (isGitHubContext) {
      core.info('🔗 GitHub context detected, posting results...');

      // Get all findings
      const allFindings = report.results.flatMap(r => r.findings);

      // Set outputs
      github.setOutputs(allFindings);

      // Post PR comment
      await github.postPRComment(report.summary, allFindings);

      // Create check run
      await github.createCheckRun(report.results);

      // Post annotations for critical/high findings
      await github.postAnnotations(report.results);

      // Check if should fail
      if (github.shouldFail(failOn, allFindings)) {
        const failCount = allFindings.filter(f => {
          const severityOrder: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info'];
          return severityOrder.indexOf(f.severity) <= severityOrder.indexOf(failOn);
        }).length;

        core.setFailed(`Security scan failed: ${failCount} finding(s) with severity >= ${failOn} detected`);
      } else {
        core.info('✅ Security scan passed');
      }
    } else {
      // Local/CLI mode
      const allFindings = report.results.flatMap(r => r.findings);
      github.setOutputs(allFindings);

      // Print summary
      console.log('\n' + '='.repeat(60));
      console.log(report.summary);
      console.log('='.repeat(60) + '\n');

      // Check if should fail
      const severityOrder: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info'];
      const failIndex = severityOrder.indexOf(failOn);

      const failCount = allFindings.filter(f =>
        severityOrder.indexOf(f.severity) <= failIndex
      ).length;

      if (failCount > 0) {
        core.setFailed(`Security scan failed: ${failCount} finding(s) with severity >= ${failOn} detected`);
      }
    }

    core.info('✅ Security scan completed successfully');

  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    core.setFailed(`Security scan failed: ${message}`);
  }
}

// Run the action
run();
