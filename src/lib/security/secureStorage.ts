/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                    VEXX AI - SECURE STORAGE MODULE                            ║
 * ║                                                                                ║
 * ║  This module provides encrypted storage capabilities for sensitive data       ║
 * ║  using the encryption utilities from the encryption module.                   ║
 * ║                                                                                ║
 * ║  Features:                                                                    ║
 * ║  - Automatic encryption/decryption of stored data                            ║
 * ║  - Integrity verification on retrieval                                       ║
 * ║  - Secure key management                                                     ║
 * ║  - Session-based temporary storage                                           ║
 * ║  - Audit logging for all operations                                          ║
 * ║                                                                                ║
 * ║  Author: VexX AI Security Team                                               ║
 * ║  Version: 2.0.0                                                               ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

import {
  encryptJSON,
  decryptJSON,
  computeSHA256Hash,
  generateSecureId,
  EncryptionResult,
} from './encryption';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Storage entry metadata
 */
export interface StorageEntryMetadata {
  /** Unique identifier for the entry */
  id: string;
  /** Key used to store the entry */
  key: string;
  /** Timestamp when the entry was created */
  createdAt: number;
  /** Timestamp when the entry was last updated */
  updatedAt: number;
  /** Timestamp when the entry expires (optional) */
  expiresAt?: number;
  /** Hash of the original data for integrity verification */
  dataHash: string;
  /** Size of the encrypted data in bytes */
  encryptedSize: number;
  /** Version of the storage format */
  version: string;
}

/**
 * Complete storage entry with encrypted data
 */
export interface SecureStorageEntry<T = unknown> {
  /** Entry metadata */
  metadata: StorageEntryMetadata;
  /** Encrypted data */
  encryptedData: EncryptionResult;
  /** Type hint for deserialization */
  typeHint: string;
}

/**
 * Storage operation result
 */
export interface StorageOperationResult<T = unknown> {
  /** Whether the operation was successful */
  success: boolean;
  /** The data if operation was successful */
  data?: T;
  /** Error message if operation failed */
  error?: string;
  /** Metadata about the operation */
  metadata?: StorageEntryMetadata;
}

/**
 * Storage audit log entry
 */
export interface StorageAuditEntry {
  /** Timestamp of the operation */
  timestamp: number;
  /** Type of operation */
  operation: 'read' | 'write' | 'delete' | 'clear' | 'expire';
  /** Key affected */
  key: string;
  /** Whether the operation was successful */
  success: boolean;
  /** Additional details */
  details?: string;
}

/**
 * Storage statistics
 */
export interface StorageStatistics {
  /** Total number of entries */
  totalEntries: number;
  /** Total size of all encrypted data */
  totalSize: number;
  /** Number of expired entries */
  expiredEntries: number;
  /** Storage utilization percentage */
  utilizationPercent: number;
  /** Last audit timestamp */
  lastAuditTimestamp: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const STORAGE_PREFIX = 'vexai_secure_';
const METADATA_KEY = `${STORAGE_PREFIX}metadata`;
const AUDIT_KEY = `${STORAGE_PREFIX}audit_log`;
const STORAGE_VERSION = '2.0.0';
const MAX_AUDIT_ENTRIES = 1000;
const MAX_STORAGE_SIZE = 5 * 1024 * 1024; // 5MB limit

// ═══════════════════════════════════════════════════════════════════════════════
// SECURE STORAGE CLASS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * SecureStorage provides encrypted local storage capabilities
 */
export class SecureStorage {
  private static instance: SecureStorage | null = null;
  private auditLog: StorageAuditEntry[] = [];
  private initialized: boolean = false;
  
  /**
   * Private constructor for singleton pattern
   */
  private constructor() {
    this.initialize();
  }
  
  /**
   * Gets the singleton instance of SecureStorage
   */
  public static getInstance(): SecureStorage {
    if (!SecureStorage.instance) {
      SecureStorage.instance = new SecureStorage();
    }
    return SecureStorage.instance;
  }
  
  /**
   * Initializes the secure storage system
   */
  private initialize(): void {
    try {
      // Load existing audit log
      const storedAuditLog = localStorage.getItem(AUDIT_KEY);
      if (storedAuditLog) {
        this.auditLog = JSON.parse(storedAuditLog);
      }
      
      // Clean expired entries on initialization
      this.cleanExpiredEntries();
      
      this.initialized = true;
      this.logAuditEntry('write', 'system', true, 'Storage initialized');
    } catch (error) {
      console.error('Failed to initialize secure storage:', error);
      this.auditLog = [];
    }
  }
  
  /**
   * Logs an audit entry
   */
  private logAuditEntry(
    operation: StorageAuditEntry['operation'],
    key: string,
    success: boolean,
    details?: string
  ): void {
    const entry: StorageAuditEntry = {
      timestamp: Date.now(),
      operation,
      key,
      success,
      details,
    };
    
    this.auditLog.unshift(entry);
    
    // Limit audit log size
    if (this.auditLog.length > MAX_AUDIT_ENTRIES) {
      this.auditLog = this.auditLog.slice(0, MAX_AUDIT_ENTRIES);
    }
    
    // Persist audit log
    try {
      localStorage.setItem(AUDIT_KEY, JSON.stringify(this.auditLog));
    } catch (error) {
      console.error('Failed to persist audit log:', error);
    }
  }
  
  /**
   * Generates a storage key with prefix
   */
  private getStorageKey(key: string): string {
    return `${STORAGE_PREFIX}${key}`;
  }
  
  /**
   * Cleans expired entries from storage
   */
  public cleanExpiredEntries(): number {
    let cleanedCount = 0;
    const now = Date.now();
    
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith(STORAGE_PREFIX) && key !== AUDIT_KEY && key !== METADATA_KEY) {
          try {
            const entryStr = localStorage.getItem(key);
            if (entryStr) {
              const entry: SecureStorageEntry = JSON.parse(entryStr);
              if (entry.metadata.expiresAt && entry.metadata.expiresAt < now) {
                localStorage.removeItem(key);
                cleanedCount++;
                this.logAuditEntry('expire', key, true, 'Entry expired and removed');
              }
            }
          } catch {
            // Skip malformed entries
          }
        }
      }
    } catch (error) {
      console.error('Error cleaning expired entries:', error);
    }
    
    return cleanedCount;
  }
  
  /**
   * Stores data securely with encryption
   */
  public async setItem<T>(
    key: string,
    data: T,
    options?: {
      expiresIn?: number;
      password?: string;
    }
  ): Promise<StorageOperationResult<T>> {
    try {
      const storageKey = this.getStorageKey(key);
      const dataString = JSON.stringify(data);
      const dataHash = await computeSHA256Hash(dataString);
      
      // Encrypt the data
      const encryptedData = await encryptJSON(data, options?.password);
      
      // Create metadata
      const metadata: StorageEntryMetadata = {
        id: generateSecureId(16),
        key,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        expiresAt: options?.expiresIn ? Date.now() + options.expiresIn : undefined,
        dataHash,
        encryptedSize: JSON.stringify(encryptedData).length,
        version: STORAGE_VERSION,
      };
      
      // Create storage entry
      const entry: SecureStorageEntry<T> = {
        metadata,
        encryptedData,
        typeHint: typeof data,
      };
      
      // Check storage limits
      const entrySize = JSON.stringify(entry).length;
      const currentSize = this.getStorageSize();
      
      if (currentSize + entrySize > MAX_STORAGE_SIZE) {
        this.logAuditEntry('write', key, false, 'Storage limit exceeded');
        return {
          success: false,
          error: 'Storage limit exceeded',
        };
      }
      
      // Store encrypted entry
      localStorage.setItem(storageKey, JSON.stringify(entry));
      
      this.logAuditEntry('write', key, true, `Stored ${entrySize} bytes`);
      
      return {
        success: true,
        data,
        metadata,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logAuditEntry('write', key, false, errorMessage);
      return {
        success: false,
        error: errorMessage,
      };
    }
  }
  
  /**
   * Retrieves and decrypts stored data
   */
  public async getItem<T>(
    key: string,
    options?: {
      password?: string;
    }
  ): Promise<StorageOperationResult<T>> {
    try {
      const storageKey = this.getStorageKey(key);
      const entryStr = localStorage.getItem(storageKey);
      
      if (!entryStr) {
        this.logAuditEntry('read', key, false, 'Key not found');
        return {
          success: false,
          error: 'Key not found',
        };
      }
      
      const entry: SecureStorageEntry<T> = JSON.parse(entryStr);
      
      // Check expiration
      if (entry.metadata.expiresAt && entry.metadata.expiresAt < Date.now()) {
        localStorage.removeItem(storageKey);
        this.logAuditEntry('read', key, false, 'Entry expired');
        return {
          success: false,
          error: 'Entry has expired',
        };
      }
      
      // Decrypt data
      const decryptedData = await decryptJSON<T>(entry.encryptedData, options?.password);
      
      if (decryptedData === null) {
        this.logAuditEntry('read', key, false, 'Decryption failed');
        return {
          success: false,
          error: 'Failed to decrypt data',
        };
      }
      
      // Verify integrity
      const currentHash = await computeSHA256Hash(JSON.stringify(decryptedData));
      if (currentHash !== entry.metadata.dataHash) {
        this.logAuditEntry('read', key, false, 'Integrity check failed');
        return {
          success: false,
          error: 'Data integrity verification failed',
        };
      }
      
      this.logAuditEntry('read', key, true);
      
      return {
        success: true,
        data: decryptedData,
        metadata: entry.metadata,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logAuditEntry('read', key, false, errorMessage);
      return {
        success: false,
        error: errorMessage,
      };
    }
  }
  
  /**
   * Removes an item from storage
   */
  public removeItem(key: string): StorageOperationResult {
    try {
      const storageKey = this.getStorageKey(key);
      const exists = localStorage.getItem(storageKey) !== null;
      
      if (!exists) {
        this.logAuditEntry('delete', key, false, 'Key not found');
        return {
          success: false,
          error: 'Key not found',
        };
      }
      
      localStorage.removeItem(storageKey);
      this.logAuditEntry('delete', key, true);
      
      return {
        success: true,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logAuditEntry('delete', key, false, errorMessage);
      return {
        success: false,
        error: errorMessage,
      };
    }
  }
  
  /**
   * Checks if a key exists in storage
   */
  public hasItem(key: string): boolean {
    const storageKey = this.getStorageKey(key);
    return localStorage.getItem(storageKey) !== null;
  }
  
  /**
   * Gets all stored keys
   */
  public getKeys(): string[] {
    const keys: string[] = [];
    
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(STORAGE_PREFIX) && key !== AUDIT_KEY && key !== METADATA_KEY) {
        keys.push(key.replace(STORAGE_PREFIX, ''));
      }
    }
    
    return keys;
  }
  
  /**
   * Clears all secure storage
   */
  public clear(): StorageOperationResult {
    try {
      const keys = this.getKeys();
      keys.forEach(key => {
        localStorage.removeItem(this.getStorageKey(key));
      });
      
      this.logAuditEntry('clear', 'all', true, `Cleared ${keys.length} entries`);
      
      return {
        success: true,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logAuditEntry('clear', 'all', false, errorMessage);
      return {
        success: false,
        error: errorMessage,
      };
    }
  }
  
  /**
   * Gets storage size in bytes
   */
  public getStorageSize(): number {
    let size = 0;
    
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(STORAGE_PREFIX)) {
        const value = localStorage.getItem(key);
        if (value) {
          size += key.length + value.length;
        }
      }
    }
    
    return size;
  }
  
  /**
   * Gets storage statistics
   */
  public getStatistics(): StorageStatistics {
    let totalEntries = 0;
    let totalSize = 0;
    let expiredEntries = 0;
    const now = Date.now();
    
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(STORAGE_PREFIX) && key !== AUDIT_KEY && key !== METADATA_KEY) {
        totalEntries++;
        const value = localStorage.getItem(key);
        if (value) {
          totalSize += value.length;
          
          try {
            const entry: SecureStorageEntry = JSON.parse(value);
            if (entry.metadata.expiresAt && entry.metadata.expiresAt < now) {
              expiredEntries++;
            }
          } catch {
            // Skip malformed entries
          }
        }
      }
    }
    
    return {
      totalEntries,
      totalSize,
      expiredEntries,
      utilizationPercent: (totalSize / MAX_STORAGE_SIZE) * 100,
      lastAuditTimestamp: this.auditLog[0]?.timestamp || 0,
    };
  }
  
  /**
   * Gets the audit log
   */
  public getAuditLog(limit?: number): StorageAuditEntry[] {
    return limit ? this.auditLog.slice(0, limit) : [...this.auditLog];
  }
  
  /**
   * Clears the audit log
   */
  public clearAuditLog(): void {
    this.auditLog = [];
    localStorage.removeItem(AUDIT_KEY);
  }
  
  /**
   * Exports all data (for backup purposes)
   */
  public async exportData(password?: string): Promise<string> {
    const exportData: Record<string, unknown> = {};
    const keys = this.getKeys();
    
    for (const key of keys) {
      const result = await this.getItem(key, { password });
      if (result.success) {
        exportData[key] = result.data;
      }
    }
    
    return JSON.stringify(exportData, null, 2);
  }
  
  /**
   * Imports data (for restore purposes)
   */
  public async importData(
    dataString: string,
    options?: {
      password?: string;
      overwrite?: boolean;
    }
  ): Promise<StorageOperationResult> {
    try {
      const data = JSON.parse(dataString);
      
      for (const [key, value] of Object.entries(data)) {
        if (!options?.overwrite && this.hasItem(key)) {
          continue;
        }
        await this.setItem(key, value, { password: options?.password });
      }
      
      return {
        success: true,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Import failed',
      };
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SINGLETON INSTANCE EXPORT
// ═══════════════════════════════════════════════════════════════════════════════

export const secureStorage = SecureStorage.getInstance();

// ═══════════════════════════════════════════════════════════════════════════════
// CONVENIENCE FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Shorthand for setting a secure item
 */
export async function setSecureItem<T>(
  key: string,
  data: T,
  options?: { expiresIn?: number; password?: string }
): Promise<boolean> {
  const result = await secureStorage.setItem(key, data, options);
  return result.success;
}

/**
 * Shorthand for getting a secure item
 */
export async function getSecureItem<T>(
  key: string,
  options?: { password?: string }
): Promise<T | null> {
  const result = await secureStorage.getItem<T>(key, options);
  return result.success ? (result.data ?? null) : null;
}

/**
 * Shorthand for removing a secure item
 */
export function removeSecureItem(key: string): boolean {
  const result = secureStorage.removeItem(key);
  return result.success;
}

export default secureStorage;
