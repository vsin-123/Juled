import * as fs from 'fs';
import * as path from 'path';
import { minimatch } from 'minimatch';
import { FileDetectionResult } from '../types';
import { FILE_TYPE_DEFINITIONS, EXTENSION_TO_TYPE_MAP, FILENAME_TO_TYPE_MAP } from './file-types';

export class FileDetector {
  private contentSampleSize: number = 4096;

  public detectFileType(filePath: string): FileDetectionResult {
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath).toLowerCase();
    const normalizedPath = filePath.toLowerCase();

    let detectedType: string | undefined;
    let confidence = 0;

    // Check exact filename match first (highest confidence)
    if (FILENAME_TO_TYPE_MAP.has(basename)) {
      detectedType = FILENAME_TO_TYPE_MAP.get(basename);
      confidence = 1.0;
    }

    // Check extension match
    if (!detectedType && ext) {
      if (EXTENSION_TO_TYPE_MAP.has(ext)) {
        detectedType = EXTENSION_TO_TYPE_MAP.get(ext);
        confidence = 0.9;
      }
    }

    // Try content analysis if still not detected
    if (!detectedType && fs.existsSync(filePath)) {
      const contentResult = this.analyzeContent(filePath);
      if (contentResult) {
        detectedType = contentResult.type;
        confidence = contentResult.confidence;
      }
    }

    // Default to unknown
    if (!detectedType) {
      detectedType = 'unknown';
      confidence = 0.0;
    }

    const contentSample = this.readContentSample(filePath);

    return {
      filePath,
      detectedType,
      confidence,
      extension: ext,
      contentSample
    };
  }

  private analyzeContent(filePath: string): { type: string; confidence: number } | null {
    try {
      const content = fs.readFileSync(filePath, 'utf-8').slice(0, this.contentSampleSize);

      // SQL detection
      if (this.isSQLContent(content)) {
        return { type: 'sql', confidence: 0.85 };
      }

      // JSON detection
      if (this.isJSONContent(content)) {
        return { type: 'json', confidence: 0.95 };
      }

      // YAML detection
      if (this.isYAMLContent(content)) {
        return { type: 'yaml', confidence: 0.9 };
      }

      // XML detection
      if (this.isXMLContent(content)) {
        return { type: 'xml', confidence: 0.95 };
      }

      // Dockerfile detection
      if (this.isDockerfileContent(content, filePath)) {
        return { type: 'dockerfile', confidence: 0.95 };
      }

      // Terraform detection
      if (this.isTerraformContent(content)) {
        return { type: 'terraform', confidence: 0.9 };
      }

      // HTML detection
      if (this.isHTMLContent(content)) {
        return { type: 'html', confidence: 0.95 };
      }

      // CSV detection
      if (this.isCSVContent(content)) {
        return { type: 'csv', confidence: 0.8 };
      }

      // Properties file detection
      if (this.isPropertiesContent(content)) {
        return { type: 'properties', confidence: 0.85 };
      }

      // Makefile detection
      if (this.isMakefileContent(content, filePath)) {
        return { type: 'makefile', confidence: 0.95 };
      }

      // Shell script detection
      if (this.isShellScriptContent(content)) {
        return { type: 'shell', confidence: 0.9 };
      }

      return null;
    } catch {
      return null;
    }
  }

  private isSQLContent(content: string): boolean {
    const sqlPatterns = [
      /^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|GRANT|REVOKE)\s/i,
      /\b(FROM|WHERE|JOIN|GROUP\s+BY|ORDER\s+BY|HAVING)\b/i,
      /\b(TABLE|DATABASE|INDEX|VIEW|TRIGGER|PROCEDURE)\b/i
    ];
    return sqlPatterns.some(pattern => pattern.test(content));
  }

  private isJSONContent(content: string): boolean {
    const trimmed = content.trim();
    return (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
           (trimmed.startsWith('[') && trimmed.endsWith(']'));
  }

  private isYAMLContent(content: string): boolean {
    const yamlPatterns = [
      /^---\s*$/m,
      /^\w+:\s/m,
      /^-\s+\w+/m,
      /\w+:\s*\n\s+-/m
    ];
    return yamlPatterns.some(pattern => pattern.test(content));
  }

  private isXMLContent(content: string): boolean {
    return content.trim().startsWith('<?xml') ||
           /^\s*<\w+[^>]*>/.test(content);
  }

  private isDockerfileContent(content: string, filePath: string): boolean {
    const dockerfilePatterns = [
      /^FROM\s+/im,
      /^RUN\s+/im,
      /^CMD\s+/im,
      /^ENTRYPOINT\s+/im,
      /^COPY\s+/im,
      /^ADD\s+/im
    ];
    const isDockerfileName = /dockerfile/i.test(path.basename(filePath));
    const hasDockerfileInstructions = dockerfilePatterns.some(pattern => pattern.test(content));
    return isDockerfileName || (hasDockerfileInstructions && content.includes('FROM'));
  }

  private isTerraformContent(content: string): boolean {
    const terraformPatterns = [
      /resource\s+"\w+"\s+"/,
      /variable\s+"/,
      /provider\s+"/,
      /module\s+"/,
      /output\s+"/
    ];
    return terraformPatterns.some(pattern => pattern.test(content));
  }

  private isHTMLContent(content: string): boolean {
    return /<html|<!DOCTYPE html|<head|<body|<div|<script|<style/i.test(content);
  }

  private isCSVContent(content: string): boolean {
    const lines = content.split('\n').slice(0, 5);
    if (lines.length < 2) return false;
    const commaCount = lines[0].split(',').length;
    return commaCount > 2 && lines.slice(1).every(line =>
      line.split(',').length === commaCount || line.trim() === ''
    );
  }

  private isPropertiesContent(content: string): boolean {
    const propertiesPattern = /^\w+[\.\w]*\s*=\s*.+$/m;
    const lines = content.split('\n').slice(0, 10);
    const matchingLines = lines.filter(line => propertiesPattern.test(line)).length;
    return matchingLines >= 2;
  }

  private isMakefileContent(content: string, filePath: string): boolean {
    const makefilePatterns = [
      /^\w+:\s*\n/,
      /^[\w-]+:\s*[^=]*$/m,
      /^\.PHONY:/m
    ];
    const isMakefileName = /^[Mm]akefile/.test(path.basename(filePath));
    const hasMakefileSyntax = makefilePatterns.some(pattern => pattern.test(content));
    return isMakefileName || hasMakefileSyntax;
  }

  private isShellScriptContent(content: string): boolean {
    const shellPatterns = [
      /^#![\/\w]*\/(bash|sh|zsh|ksh)/m,
      /^\s*if\s+\[/m,
      /^\s*for\s+\w+\s+in/m,
      /^\s*while\s+\[/m,
      /^\s*function\s+\w+\s*\(\)/m
    ];
    return shellPatterns.some(pattern => pattern.test(content));
  }

  private readContentSample(filePath: string): string | undefined {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      return content.slice(0, this.contentSampleSize);
    } catch {
      return undefined;
    }
  }

  public shouldExcludeFile(filePath: string, excludePatterns: string[]): boolean {
    const normalizedPath = filePath.replace(/\\/g, '/');
    return excludePatterns.some(pattern => {
      if (pattern.includes('*') || pattern.includes('?')) {
        return minimatch(normalizedPath, pattern, { matchBase: true, dot: true });
      }
      return normalizedPath.includes(pattern);
    });
  }

  public getFilesToScan(
    directory: string,
    includeExtensions?: string[],
    excludeExtensions?: string[],
    excludePatterns: string[] = []
  ): string[] {
    const files: string[] = [];

    const scanDirectory = (dir: string) => {
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          const relativePath = path.relative(directory, fullPath);

          if (this.shouldExcludeFile(relativePath, excludePatterns)) {
            continue;
          }

          if (entry.isDirectory()) {
            scanDirectory(fullPath);
          } else if (entry.isFile()) {
            const ext = path.extname(entry.name).toLowerCase();

            if (excludeExtensions && excludeExtensions.includes(ext)) {
              continue;
            }

            if (!includeExtensions || includeExtensions.includes(ext)) {
              files.push(fullPath);
            }
          }
        }
      } catch (error) {
        // Skip directories we can't read
      }
    };

    scanDirectory(directory);
    return files;
  }

  public getFileTypeDefinition(typeName: string) {
    return FILE_TYPE_DEFINITIONS.find(ft => ft.name === typeName);
  }

  public getScannerForFileType(typeName: string): string | undefined {
    const definition = this.getFileTypeDefinition(typeName);
    return definition?.scanner;
  }
}
