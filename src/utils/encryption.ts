import * as crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 64;
const KEY_LENGTH = 32;
const ITERATIONS = 10000;

export class EncryptionService {
  private key: Buffer;

  constructor(encryptionKey?: string) {
    const key = encryptionKey || process.env.ENCRYPTION_KEY;
    if (!key) {
      throw new Error('Encryption key is required');
    }
    this.key = crypto.scryptSync(key, 'salt', KEY_LENGTH);
  }

  encrypt(plaintext: string): string {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.key, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    // Format: iv:authTag:encrypted
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  decrypt(encryptedData: string): string {
    const parts = encryptedData.split(':');
    
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }

    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];

    const decipher = crypto.createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  hash(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  generateToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  verifySignature(data: string, signature: string, secret: string): boolean {
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('hex');
    
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }

  createSignature(data: string, secret: string): string {
    return crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('hex');
  }
}

// Singleton instance
let encryptionService: EncryptionService | null = null;

export function getEncryptionService(encryptionKey?: string): EncryptionService {
  if (!encryptionService) {
    encryptionService = new EncryptionService(encryptionKey);
  }
  return encryptionService;
}

export function initializeEncryption(encryptionKey: string): void {
  encryptionService = new EncryptionService(encryptionKey);
}

export function encryptAPIKey(apiKey: string, encryptionKey?: string): string {
  const service = getEncryptionService(encryptionKey);
  return service.encrypt(apiKey);
}

export function decryptAPIKey(encryptedKey: string, encryptionKey?: string): string {
  const service = getEncryptionService(encryptionKey);
  return service.decrypt(encryptedKey);
}
