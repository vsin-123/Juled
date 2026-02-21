import { ScannerEngine } from '../../src/core/scanner-engine';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('ScannerEngine', () => {
  let engine: ScannerEngine;
  let tempDir: string;

  beforeEach(() => {
    engine = new ScannerEngine();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanner-engine-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe('scan', () => {
    it('should scan files and return report', async () => {
      // Create test files
      fs.writeFileSync(path.join(tempDir, 'test.sql'), 'SELECT * FROM users WHERE id = 1;');
      fs.writeFileSync(path.join(tempDir, 'config.json'), '{"name": "test"}');

      const report = await engine.scan({
        directory: tempDir,
        parallel: false
      });

      expect(report).toHaveProperty('scanId');
      expect(report).toHaveProperty('totalFiles');
      expect(report).toHaveProperty('totalFindings');
      expect(report).toHaveProperty('findingsBySeverity');
      expect(report).toHaveProperty('summary');
      expect(report).toHaveProperty('results');
    });

    it('should respect exclude paths', async () => {
      fs.mkdirSync(path.join(tempDir, 'node_modules'), { recursive: true });
      fs.writeFileSync(path.join(tempDir, 'node_modules', 'test.sql'), 'SELECT password FROM users;');
      fs.writeFileSync(path.join(tempDir, 'test.sql'), 'SELECT 1;');

      const report = await engine.scan({
        directory: tempDir,
        excludePaths: ['node_modules'],
        parallel: false
      });

      // Should only scan the test.sql outside node_modules
      const nodeModulesFiles = report.results.filter(r => r.filePath.includes('node_modules'));
      expect(nodeModulesFiles).toHaveLength(0);
    });

    it('should detect secrets in SQL files', async () => {
      fs.writeFileSync(
        path.join(tempDir, 'test.sql'),
        `CREATE USER admin WITH PASSWORD 'supersecret123';
         INSERT INTO users VALUES (1, 'admin', 'password123');`
      );

      const report = await engine.scan({
        directory: tempDir,
        parallel: false
      });

      const findings = report.results.flatMap(r => r.findings);
      const passwordFindings = findings.filter(f =>
        f.message.toLowerCase().includes('password') ||
        f.category === 'hardcoded-secrets'
      );

      expect(passwordFindings.length).toBeGreaterThan(0);
    });
  });

  describe('generateMarkdownReport', () => {
    it('should generate valid markdown report', () => {
      const mockReport = {
        scanId: 'test-123',
        scannedAt: new Date(),
        totalFiles: 5,
        totalFindings: 3,
        findingsBySeverity: {
          critical: 1,
          high: 1,
          medium: 1,
          low: 0,
          info: 0
        },
        findingsByCategory: { 'sql-injection': 2, 'hardcoded-secrets': 1 },
        findingsByOwasp: {},
        results: [],
        summary: 'Test summary'
      };

      const markdown = engine.generateMarkdownReport(mockReport);

      expect(markdown).toContain('# 🔒 Security Scan Report');
      expect(markdown).toContain('test-123');
      expect(markdown).toContain('Critical');
      expect(markdown).toContain('High');
    });
  });

  describe('generateSARIFReport', () => {
    it('should generate valid SARIF report', () => {
      const mockReport = {
        scanId: 'test-123',
        scannedAt: new Date(),
        totalFiles: 5,
        totalFindings: 3,
        findingsBySeverity: {
          critical: 1,
          high: 1,
          medium: 1,
          low: 0,
          info: 0
        },
        findingsByCategory: {},
        findingsByOwasp: {},
        results: [],
        summary: 'Test summary'
      };

      const sarif = engine.generateSARIFReport(mockReport);
      const parsed = JSON.parse(sarif);

      expect(parsed).toHaveProperty('$schema');
      expect(parsed).toHaveProperty('version', '2.1.0');
      expect(parsed).toHaveProperty('runs');
      expect(parsed.runs).toHaveLength(1);
    });
  });
});
