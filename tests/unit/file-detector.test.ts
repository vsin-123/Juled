import { FileDetector } from '../../src/core/file-detector';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('FileDetector', () => {
  let detector: FileDetector;
  let tempDir: string;

  beforeEach(() => {
    detector = new FileDetector();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'security-scanner-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe('detectFileType', () => {
    it('should detect SQL files', () => {
      const sqlFile = path.join(tempDir, 'test.sql');
      fs.writeFileSync(sqlFile, 'SELECT * FROM users;');

      const result = detector.detectFileType(sqlFile);
      expect(result.detectedType).toBe('sql');
      expect(result.confidence).toBeGreaterThan(0);
    });

    it('should detect JSON files', () => {
      const jsonFile = path.join(tempDir, 'test.json');
      fs.writeFileSync(jsonFile, '{"key": "value"}');

      const result = detector.detectFileType(jsonFile);
      expect(result.detectedType).toBe('json');
    });

    it('should detect YAML files', () => {
      const yamlFile = path.join(tempDir, 'test.yml');
      fs.writeFileSync(yamlFile, 'key: value\nlist:\n  - item1\n  - item2');

      const result = detector.detectFileType(yamlFile);
      expect(result.detectedType).toBe('yaml');
    });

    it('should detect Dockerfiles', () => {
      const dockerfile = path.join(tempDir, 'Dockerfile');
      fs.writeFileSync(dockerfile, 'FROM node:18\nRUN npm install');

      const result = detector.detectFileType(dockerfile);
      expect(result.detectedType).toBe('dockerfile');
    });

    it('should detect Terraform files', () => {
      const tfFile = path.join(tempDir, 'main.tf');
      fs.writeFileSync(tfFile, 'resource "aws_instance" "example" {}');

      const result = detector.detectFileType(tfFile);
      expect(result.detectedType).toBe('terraform');
    });
  });

  describe('shouldExcludeFile', () => {
    it('should exclude node_modules', () => {
      const shouldExclude = detector.shouldExcludeFile('src/node_modules/test.js', ['node_modules']);
      expect(shouldExclude).toBe(true);
    });

    it('should not exclude regular files', () => {
      const shouldExclude = detector.shouldExcludeFile('src/index.js', ['node_modules']);
      expect(shouldExclude).toBe(false);
    });

    it('should handle glob patterns', () => {
      const shouldExclude = detector.shouldExcludeFile('src/test.spec.js', ['*.spec.js']);
      expect(shouldExclude).toBe(true);
    });
  });

  describe('getFilesToScan', () => {
    it('should return files matching extensions', () => {
      fs.writeFileSync(path.join(tempDir, 'test.sql'), 'SELECT 1;');
      fs.writeFileSync(path.join(tempDir, 'test.txt'), 'hello');

      const files = detector.getFilesToScan(tempDir, ['.sql']);
      expect(files).toHaveLength(1);
      expect(files[0]).toContain('test.sql');
    });

    it('should exclude specified paths', () => {
      fs.mkdirSync(path.join(tempDir, 'node_modules'), { recursive: true });
      fs.writeFileSync(path.join(tempDir, 'node_modules', 'test.sql'), 'SELECT 1;');
      fs.writeFileSync(path.join(tempDir, 'test.sql'), 'SELECT 1;');

      const files = detector.getFilesToScan(tempDir, ['.sql'], [], ['node_modules']);
      expect(files).toHaveLength(1);
      expect(files[0]).not.toContain('node_modules');
    });
  });
});
