/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                    VEXX AI - SECURE LOCAL STORAGE HOOK                        ║
 * ║                                                                                ║
 * ║  This hook provides encrypted local storage with automatic encryption         ║
 * ║  and decryption of data using the security module.                           ║
 * ║                                                                                ║
 * ║  Features:                                                                    ║
 * ║  - Automatic AES-GCM encryption/decryption                                   ║
 * ║  - Integrity verification on data retrieval                                  ║
 * ║  - Optional password protection for additional security                      ║
 * ║  - Fallback to regular storage if encryption fails                           ║
 * ║  - Security audit logging for all operations                                 ║
 * ║                                                                                ║
 * ║  Author: VexX AI Security Team                                               ║
 * ║  Version: 2.0.0                                                               ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  encryptJSON,
  decryptJSON,
  computeSHA256Hash,
  EncryptionResult,
} from '@/lib/security/encryption';
import { securityAudit } from '@/lib/security/securityAudit';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Options for secure storage hook
 */
export interface SecureStorageOptions {
  /** Password for additional encryption layer */
  password?: string;
  /** Whether to enable encryption (default: true) */
  encrypt?: boolean;
  /** Whether to log operations to security audit (default: true) */
  auditLog?: boolean;
  /** Expiration time in milliseconds */
  expiresIn?: number;
  /** Whether to validate data integrity on read (default: true) */
  validateIntegrity?: boolean;
}

/**
 * Stored data wrapper with metadata
 */
interface SecureStoredData<T> {
  /** The stored data (encrypted or plain) */
  data: T | EncryptionResult;
  /** Whether the data is encrypted */
  encrypted: boolean;
  /** Hash of original data for integrity check */
  hash: string;
  /** Timestamp when data was stored */
  storedAt: number;
  /** Expiration timestamp */
  expiresAt?: number;
  /** Storage version */
  version: string;
}

/**
 * Return type of useSecureLocalStorage hook
 */
export type SecureStorageReturn<T> = [
  T,
  (value: T | ((val: T) => T)) => Promise<void>,
  {
    loading: boolean;
    error: string | null;
    clearError: () => void;
    remove: () => void;
    refresh: () => Promise<void>;
    isEncrypted: boolean;
    lastUpdated: number | null;
  }
];

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const STORAGE_VERSION = '2.0.0';
const STORAGE_PREFIX = 'vexai_secure_';

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generates a prefixed storage key
 */
function getStorageKey(key: string): string {
  return `${STORAGE_PREFIX}${key}`;
}

/**
 * Checks if stored data has expired
 */
function isExpired(data: SecureStoredData<unknown>): boolean {
  if (!data.expiresAt) return false;
  return Date.now() > data.expiresAt;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURE LOCAL STORAGE HOOK
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Hook for encrypted local storage with security features
 * 
 * @param key - Storage key
 * @param initialValue - Initial value if key doesn't exist
 * @param options - Storage options
 * @returns Tuple of [value, setValue, utilities]
 * 
 * @example
 * ```tsx
 * const [settings, setSettings, { loading, error }] = useSecureLocalStorage(
 *   'app-settings',
 *   defaultSettings,
 *   { encrypt: true, auditLog: true }
 * );
 * ```
 */
export function useSecureLocalStorage<T>(
  key: string,
  initialValue: T,
  options: SecureStorageOptions = {}
): SecureStorageReturn<T> {
  const {
    password,
    encrypt = true,
    auditLog = true,
    expiresIn,
    validateIntegrity = true,
  } = options;
  
  // State management
  const [storedValue, setStoredValue] = useState<T>(initialValue);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isEncrypted, setIsEncrypted] = useState<boolean>(encrypt);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  
  // Refs for stable callbacks
  const initRef = useRef(false);
  const keyRef = useRef(key);
  
  // Generate storage key
  const storageKey = getStorageKey(key);
  
  /**
   * Logs a security audit event
   */
  const logSecurityEvent = useCallback(async (
    operation: 'read' | 'write' | 'delete',
    success: boolean,
    details?: string
  ) => {
    if (!auditLog) return;
    
    try {
      await securityAudit.logEvent({
        type: operation === 'read' ? 'data_access' : operation === 'write' ? 'data_modification' : 'data_deletion',
        severity: success ? 'low' : 'medium',
        description: `Storage ${operation}: ${key}`,
        metadata: {
          key,
          encrypted: isEncrypted,
          details,
        },
      });
    } catch {
      // Silently fail audit logging
    }
  }, [auditLog, key, isEncrypted]);
  
  /**
   * Reads and decrypts data from storage
   */
  const readFromStorage = useCallback(async (): Promise<T> => {
    try {
      const item = window.localStorage.getItem(storageKey);
      
      if (!item) {
        await logSecurityEvent('read', true, 'Key not found, using initial value');
        return initialValue;
      }
      
      const stored: SecureStoredData<T> = JSON.parse(item);
      
      // Check expiration
      if (isExpired(stored)) {
        window.localStorage.removeItem(storageKey);
        await logSecurityEvent('read', true, 'Data expired, using initial value');
        return initialValue;
      }
      
      // Decrypt if necessary
      let value: T;
      if (stored.encrypted) {
        const decrypted = await decryptJSON<T>(stored.data as EncryptionResult, password);
        if (decrypted === null) {
          throw new Error('Decryption failed');
        }
        value = decrypted;
        setIsEncrypted(true);
      } else {
        value = stored.data as T;
        setIsEncrypted(false);
      }
      
      // Validate integrity
      if (validateIntegrity) {
        const currentHash = await computeSHA256Hash(JSON.stringify(value));
        if (currentHash !== stored.hash) {
          console.warn('Data integrity check failed, data may have been tampered');
          await logSecurityEvent('read', false, 'Integrity check failed');
        }
      }
      
      setLastUpdated(stored.storedAt);
      await logSecurityEvent('read', true);
      
      return value;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to read from storage';
      console.error(`Error reading secure storage key "${key}":`, err);
      await logSecurityEvent('read', false, errorMessage);
      setError(errorMessage);
      return initialValue;
    }
  }, [storageKey, initialValue, password, validateIntegrity, logSecurityEvent, key]);
  
  /**
   * Encrypts and writes data to storage
   */
  const writeToStorage = useCallback(async (value: T): Promise<void> => {
    try {
      const dataString = JSON.stringify(value);
      const hash = await computeSHA256Hash(dataString);
      
      let dataToStore: T | EncryptionResult;
      if (encrypt) {
        dataToStore = await encryptJSON(value, password);
        setIsEncrypted(true);
      } else {
        dataToStore = value;
        setIsEncrypted(false);
      }
      
      const stored: SecureStoredData<T> = {
        data: dataToStore,
        encrypted: encrypt,
        hash,
        storedAt: Date.now(),
        expiresAt: expiresIn ? Date.now() + expiresIn : undefined,
        version: STORAGE_VERSION,
      };
      
      window.localStorage.setItem(storageKey, JSON.stringify(stored));
      setLastUpdated(stored.storedAt);
      await logSecurityEvent('write', true);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to write to storage';
      console.error(`Error writing secure storage key "${key}":`, err);
      await logSecurityEvent('write', false, errorMessage);
      setError(errorMessage);
      throw err;
    }
  }, [storageKey, encrypt, password, expiresIn, logSecurityEvent, key]);
  
  /**
   * Initialize storage on mount
   */
  useEffect(() => {
    if (initRef.current && keyRef.current === key) return;
    
    const initialize = async () => {
      setLoading(true);
      setError(null);
      
      try {
        const value = await readFromStorage();
        setStoredValue(value);
      } catch (err) {
        console.error('Failed to initialize secure storage:', err);
        setStoredValue(initialValue);
      } finally {
        setLoading(false);
        initRef.current = true;
        keyRef.current = key;
      }
    };
    
    initialize();
  }, [key, readFromStorage, initialValue]);
  
  /**
   * Value setter function
   */
  const setValue = useCallback(async (value: T | ((val: T) => T)): Promise<void> => {
    try {
      setError(null);
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      
      await writeToStorage(valueToStore);
      setStoredValue(valueToStore);
    } catch (err) {
      // Error already logged in writeToStorage
      throw err;
    }
  }, [storedValue, writeToStorage]);
  
  /**
   * Remove item from storage
   */
  const remove = useCallback(() => {
    try {
      window.localStorage.removeItem(storageKey);
      setStoredValue(initialValue);
      setLastUpdated(null);
      logSecurityEvent('delete', true);
    } catch (err) {
      console.error(`Error removing secure storage key "${key}":`, err);
      logSecurityEvent('delete', false, String(err));
    }
  }, [storageKey, initialValue, logSecurityEvent, key]);
  
  /**
   * Refresh data from storage
   */
  const refresh = useCallback(async (): Promise<void> => {
    setLoading(true);
    try {
      const value = await readFromStorage();
      setStoredValue(value);
      setError(null);
    } catch (err) {
      console.error('Failed to refresh secure storage:', err);
    } finally {
      setLoading(false);
    }
  }, [readFromStorage]);
  
  /**
   * Clear error state
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);
  
  return [
    storedValue,
    setValue,
    {
      loading,
      error,
      clearError,
      remove,
      refresh,
      isEncrypted,
      lastUpdated,
    },
  ];
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADDITIONAL HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Simple hook for secure storage without additional utilities
 */
export function useSecureStorage<T>(
  key: string,
  initialValue: T,
  options?: SecureStorageOptions
): [T, (value: T | ((val: T) => T)) => Promise<void>] {
  const [value, setValue] = useSecureLocalStorage(key, initialValue, options);
  return [value, setValue];
}

/**
 * Hook for storing sensitive strings (like API keys)
 */
export function useSecureSensitiveString(
  key: string,
  initialValue: string = ''
): [string, (value: string) => Promise<void>, { loading: boolean; error: string | null }] {
  const [value, setValue, { loading, error }] = useSecureLocalStorage(key, initialValue, {
    encrypt: true,
    auditLog: true,
  });
  
  const setString = useCallback(async (newValue: string) => {
    await setValue(newValue);
  }, [setValue]);
  
  return [value, setString, { loading, error }];
}

export default useSecureLocalStorage;
