/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                    VEXX AI - SECURITY MODULE INDEX                            ║
 * ║                                                                                ║
 * ║  This file exports all security-related modules and utilities                 ║
 * ║  providing a unified interface for the security subsystem.                    ║
 * ║                                                                                ║
 * ║  Modules included:                                                            ║
 * ║  - Encryption: AES-GCM 256-bit encryption, hashing, key derivation           ║
 * ║  - SecureStorage: Encrypted local storage with integrity verification        ║
 * ║  - SecurityAudit: Event logging, threat detection, session management        ║
 * ║                                                                                ║
 * ║  Author: VexX AI Security Team                                               ║
 * ║  Version: 2.0.0                                                               ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

// ═══════════════════════════════════════════════════════════════════════════════
// ENCRYPTION EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export {
  // Core encryption functions
  encryptData,
  decryptData,
  encryptJSON,
  decryptJSON,
  encryptSensitiveString,
  decryptSensitiveString,
  
  // Hashing functions
  computeSHA256Hash,
  computeSHA384Hash,
  computeSHA512Hash,
  computeHashWithMetadata,
  computeHMAC,
  verifyHMAC,
  
  // Password functions
  hashPassword,
  verifyPassword,
  validatePasswordStrength,
  
  // Key derivation
  deriveKeyFromPassword,
  deriveKeyWithMetadata,
  
  // Random generation
  generateSecureRandomBytes,
  generateSecureId,
  generateSecureToken,
  generateSecureOTP,
  generateSecureAPIKey,
  generateSalt,
  generateIV,
  
  // Utilities
  secureCompare,
  sanitizeHTML,
  sanitizeEmail,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  stringToUint8Array,
  uint8ArrayToString,
  
  // Constants and types
  DEFAULT_ENCRYPTION_CONFIG,
  SecurityUtils,
  
  // Type exports
  type EncryptionConfig,
  type EncryptionResult,
  type DecryptionResult,
  type HashResult,
  type DerivedKeyResult,
  type PasswordHashResult,
} from './encryption';

// ═══════════════════════════════════════════════════════════════════════════════
// SECURE STORAGE EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export {
  // SecureStorage class
  SecureStorage,
  secureStorage,
  
  // Convenience functions
  setSecureItem,
  getSecureItem,
  removeSecureItem,
  
  // Type exports
  type StorageEntryMetadata,
  type SecureStorageEntry,
  type StorageOperationResult,
  type StorageAuditEntry,
  type StorageStatistics,
} from './secureStorage';

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY AUDIT EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export {
  // SecurityAudit class
  SecurityAudit,
  securityAudit,
  
  // Type exports
  type SecuritySeverity,
  type SecurityEventType,
  type SecurityEvent,
  type SecuritySession,
  type RateLimitEntry,
  type SecurityConfig,
  type SecurityStatistics,
  type ThreatAssessment,
} from './securityAudit';

// ═══════════════════════════════════════════════════════════════════════════════
// COMBINED SECURITY INTERFACE
// ═══════════════════════════════════════════════════════════════════════════════

import { SecurityUtils } from './encryption';
import { secureStorage } from './secureStorage';
import { securityAudit } from './securityAudit';

/**
 * Combined security interface providing access to all security features
 */
export const Security = {
  /** Encryption and cryptographic utilities */
  crypto: SecurityUtils,
  
  /** Secure encrypted storage */
  storage: secureStorage,
  
  /** Security auditing and monitoring */
  audit: securityAudit,
  
  /**
   * Initialize the security system
   */
  async initialize(): Promise<void> {
    // Storage is initialized automatically
    // Audit is initialized automatically
    
    // Log security system initialization
    await securityAudit.logEvent({
      type: 'system_alert',
      severity: 'low',
      description: 'Security system fully initialized',
      metadata: {
        version: '2.0.0',
        modules: ['encryption', 'secureStorage', 'securityAudit'],
      },
    });
  },
  
  /**
   * Get overall security status
   */
  async getSecurityStatus(): Promise<{
    storage: import('./secureStorage').StorageStatistics;
    audit: import('./securityAudit').SecurityStatistics;
    assessment: import('./securityAudit').ThreatAssessment;
  }> {
    const storage = secureStorage.getStatistics();
    const audit = securityAudit.getStatistics();
    const assessment = await securityAudit.performThreatAssessment();
    
    return { storage, audit, assessment };
  },
  
  /**
   * Export comprehensive security report
   */
  async exportFullReport(): Promise<string> {
    const status = await this.getSecurityStatus();
    const auditReport = await securityAudit.exportSecurityReport();
    const storageData = await secureStorage.exportData();
    
    const fullReport = {
      generatedAt: new Date().toISOString(),
      version: '2.0.0',
      status,
      auditReport: JSON.parse(auditReport),
      storageKeys: secureStorage.getKeys(),
    };
    
    return JSON.stringify(fullReport, null, 2);
  },
  
  /**
   * Clear all security data (use with caution)
   */
  clearAll(): void {
    secureStorage.clear();
    securityAudit.clearAll();
  },
};

export default Security;
