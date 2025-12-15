/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                    VEXX AI - ADVANCED ENCRYPTION MODULE                       ║
 * ║                                                                                ║
 * ║  This module provides enterprise-grade encryption and decryption utilities    ║
 * ║  using the Web Crypto API with AES-GCM 256-bit encryption.                   ║
 * ║                                                                                ║
 * ║  Security Features:                                                           ║
 * ║  - AES-GCM 256-bit symmetric encryption                                       ║
 * ║  - PBKDF2 key derivation with 100,000 iterations                             ║
 * ║  - Cryptographically secure random IV generation                              ║
 * ║  - Salt-based key derivation for password protection                          ║
 * ║  - SHA-256 hashing for integrity verification                                 ║
 * ║  - Base64 encoding for safe string storage                                    ║
 * ║                                                                                ║
 * ║  Author: VexX AI Security Team                                               ║
 * ║  Version: 2.0.0                                                               ║
 * ║  Last Updated: 2024                                                           ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE DEFINITIONS AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Configuration options for encryption operations
 */
export interface EncryptionConfig {
  /** Algorithm to use for encryption */
  algorithm: 'AES-GCM' | 'AES-CBC' | 'AES-CTR';
  /** Key length in bits (128, 192, or 256) */
  keyLength: 128 | 192 | 256;
  /** Number of PBKDF2 iterations for key derivation */
  iterations: number;
  /** Salt length in bytes */
  saltLength: number;
  /** Initialization vector length in bytes */
  ivLength: number;
  /** Hash algorithm for PBKDF2 */
  hashAlgorithm: 'SHA-256' | 'SHA-384' | 'SHA-512';
}

/**
 * Result of an encryption operation
 */
export interface EncryptionResult {
  /** Base64-encoded encrypted data */
  ciphertext: string;
  /** Base64-encoded initialization vector */
  iv: string;
  /** Base64-encoded salt used for key derivation */
  salt: string;
  /** Timestamp of encryption */
  timestamp: number;
  /** Algorithm version for future compatibility */
  version: string;
  /** Checksum for integrity verification */
  checksum: string;
}

/**
 * Result of a decryption operation
 */
export interface DecryptionResult {
  /** Decrypted plaintext data */
  plaintext: string;
  /** Whether the decryption was successful */
  success: boolean;
  /** Error message if decryption failed */
  error?: string;
  /** Whether integrity check passed */
  integrityVerified: boolean;
}

/**
 * Hash result with metadata
 */
export interface HashResult {
  /** The computed hash value */
  hash: string;
  /** Algorithm used */
  algorithm: string;
  /** Timestamp of hash computation */
  timestamp: number;
}

/**
 * Key derivation result
 */
export interface DerivedKeyResult {
  /** The derived key */
  key: CryptoKey;
  /** Salt used in derivation */
  salt: Uint8Array;
  /** Number of iterations used */
  iterations: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS AND DEFAULT CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

/** Default encryption configuration with maximum security settings */
export const DEFAULT_ENCRYPTION_CONFIG: EncryptionConfig = {
  algorithm: 'AES-GCM',
  keyLength: 256,
  iterations: 100000,
  saltLength: 32,
  ivLength: 12,
  hashAlgorithm: 'SHA-256',
};

/** Current encryption version for future compatibility */
const ENCRYPTION_VERSION = '2.0.0';

/** Master encryption key derived from application secret */
const APPLICATION_SECRET = 'VexX-AI-2024-SecureKey-F7D9E2A1B4C6';

/** Secondary obfuscation layer */
const OBFUSCATION_KEY = 'x9K2mN4pQ7rT1vW3';

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Converts an ArrayBuffer to a Base64 string
 * @param buffer - The ArrayBuffer to convert
 * @returns Base64-encoded string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts a Base64 string to an ArrayBuffer
 * @param base64 - The Base64 string to convert
 * @returns Uint8Array representation
 */
export function base64ToArrayBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Converts a string to a Uint8Array using UTF-8 encoding
 * @param str - The string to convert
 * @returns Uint8Array representation
 */
export function stringToUint8Array(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Converts a Uint8Array to a string using UTF-8 decoding
 * @param array - The Uint8Array to convert
 * @returns Decoded string
 */
export function uint8ArrayToString(array: Uint8Array): string {
  return new TextDecoder().decode(array);
}

/**
 * Generates cryptographically secure random bytes
 * @param length - Number of random bytes to generate
 * @returns Uint8Array of random bytes
 */
export function generateSecureRandomBytes(length: number): Uint8Array {
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return randomBytes;
}

/**
 * Generates a unique identifier using crypto random values
 * @param length - Length of the identifier (default: 32)
 * @returns Hexadecimal string identifier
 */
export function generateSecureId(length: number = 32): string {
  const bytes = generateSecureRandomBytes(Math.ceil(length / 2));
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, length);
}

/**
 * Generates a cryptographically secure salt
 * @param length - Salt length in bytes (default: 32)
 * @returns Uint8Array salt
 */
export function generateSalt(length: number = DEFAULT_ENCRYPTION_CONFIG.saltLength): Uint8Array {
  return generateSecureRandomBytes(length);
}

/**
 * Generates a cryptographically secure initialization vector
 * @param length - IV length in bytes (default: 12 for AES-GCM)
 * @returns Uint8Array IV
 */
export function generateIV(length: number = DEFAULT_ENCRYPTION_CONFIG.ivLength): Uint8Array {
  return generateSecureRandomBytes(length);
}

// ═══════════════════════════════════════════════════════════════════════════════
// HASHING FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Computes a SHA-256 hash of the input data
 * @param data - The data to hash (string or ArrayBuffer)
 * @returns Promise resolving to hexadecimal hash string
 */
export async function computeSHA256Hash(data: string | ArrayBuffer): Promise<string> {
  const buffer = typeof data === 'string' ? stringToUint8Array(data).buffer as ArrayBuffer : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Computes a SHA-384 hash of the input data
 * @param data - The data to hash
 * @returns Promise resolving to hexadecimal hash string
 */
export async function computeSHA384Hash(data: string | ArrayBuffer): Promise<string> {
  const buffer = typeof data === 'string' ? stringToUint8Array(data).buffer as ArrayBuffer : data;
  const hashBuffer = await crypto.subtle.digest('SHA-384', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Computes a SHA-512 hash of the input data
 * @param data - The data to hash
 * @returns Promise resolving to hexadecimal hash string
 */
export async function computeSHA512Hash(data: string | ArrayBuffer): Promise<string> {
  const buffer = typeof data === 'string' ? stringToUint8Array(data).buffer as ArrayBuffer : data;
  const hashBuffer = await crypto.subtle.digest('SHA-512', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Computes a hash with metadata
 * @param data - The data to hash
 * @param algorithm - Hash algorithm to use
 * @returns Promise resolving to HashResult
 */
export async function computeHashWithMetadata(
  data: string,
  algorithm: 'SHA-256' | 'SHA-384' | 'SHA-512' = 'SHA-256'
): Promise<HashResult> {
  let hash: string;
  
  switch (algorithm) {
    case 'SHA-384':
      hash = await computeSHA384Hash(data);
      break;
    case 'SHA-512':
      hash = await computeSHA512Hash(data);
      break;
    default:
      hash = await computeSHA256Hash(data);
  }
  
  return {
    hash,
    algorithm,
    timestamp: Date.now(),
  };
}

/**
 * Computes HMAC-SHA256 for message authentication
 * @param key - The secret key
 * @param data - The data to authenticate
 * @returns Promise resolving to HMAC string
 */
export async function computeHMAC(key: string, data: string): Promise<string> {
  const keyBuffer = stringToUint8Array(key).buffer as ArrayBuffer;
  const dataBuffer = stringToUint8Array(data).buffer as ArrayBuffer;
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, dataBuffer);
  return arrayBufferToBase64(signature);
}

/**
 * Verifies an HMAC signature
 * @param key - The secret key
 * @param data - The original data
 * @param signature - The signature to verify
 * @returns Promise resolving to boolean
 */
export async function verifyHMAC(key: string, data: string, signature: string): Promise<boolean> {
  const computedSignature = await computeHMAC(key, data);
  return computedSignature === signature;
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY DERIVATION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Derives a cryptographic key from a password using PBKDF2
 * @param password - The password to derive key from
 * @param salt - Salt for key derivation
 * @param config - Encryption configuration
 * @returns Promise resolving to CryptoKey
 */
export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  config: EncryptionConfig = DEFAULT_ENCRYPTION_CONFIG
): Promise<CryptoKey> {
  // Import the password as a key
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    stringToUint8Array(password).buffer as ArrayBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  
  // Derive the AES key using PBKDF2
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations: config.iterations,
      hash: config.hashAlgorithm,
    },
    passwordKey,
    {
      name: config.algorithm,
      length: config.keyLength,
    },
    false,
    ['encrypt', 'decrypt']
  );
  
  return derivedKey;
}

/**
 * Derives a key with full metadata
 * @param password - The password to derive key from
 * @param existingSalt - Optional existing salt to use
 * @param config - Encryption configuration
 * @returns Promise resolving to DerivedKeyResult
 */
export async function deriveKeyWithMetadata(
  password: string,
  existingSalt?: Uint8Array,
  config: EncryptionConfig = DEFAULT_ENCRYPTION_CONFIG
): Promise<DerivedKeyResult> {
  const salt = existingSalt || generateSalt(config.saltLength);
  const key = await deriveKeyFromPassword(password, salt, config);
  
  return {
    key,
    salt,
    iterations: config.iterations,
  };
}

/**
 * Creates a combined key from application secret and user password
 * @param userPassword - User-provided password
 * @returns Combined key string
 */
function createCombinedKey(userPassword?: string): string {
  const baseKey = APPLICATION_SECRET;
  const obfuscatedKey = baseKey
    .split('')
    .map((char, i) => String.fromCharCode(char.charCodeAt(0) ^ OBFUSCATION_KEY.charCodeAt(i % OBFUSCATION_KEY.length)))
    .join('');
  
  if (userPassword) {
    return `${obfuscatedKey}:${userPassword}`;
  }
  
  return obfuscatedKey;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENCRYPTION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Encrypts data using AES-GCM with the specified configuration
 * @param plaintext - The data to encrypt
 * @param password - Optional password for additional security layer
 * @param config - Encryption configuration
 * @returns Promise resolving to EncryptionResult
 */
export async function encryptData(
  plaintext: string,
  password?: string,
  config: EncryptionConfig = DEFAULT_ENCRYPTION_CONFIG
): Promise<EncryptionResult> {
  try {
    // Generate cryptographic parameters
    const salt = generateSalt(config.saltLength);
    const iv = generateIV(config.ivLength);
    
    // Create combined key
    const combinedKey = createCombinedKey(password);
    
    // Derive encryption key
    const encryptionKey = await deriveKeyFromPassword(combinedKey, salt, config);
    
    // Convert plaintext to bytes
    const plaintextBytes = stringToUint8Array(plaintext);
    
    // Perform encryption
    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: config.algorithm,
        iv: iv.buffer as ArrayBuffer,
      },
      encryptionKey,
      plaintextBytes.buffer as ArrayBuffer
    );
    
    // Compute checksum for integrity verification
    const checksum = await computeSHA256Hash(plaintext);
    
    // Return encrypted result
    return {
      ciphertext: arrayBufferToBase64(encryptedBuffer),
      iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
      salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
      timestamp: Date.now(),
      version: ENCRYPTION_VERSION,
      checksum: checksum.slice(0, 16), // Store truncated checksum
    };
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt data');
  }
}

/**
 * Decrypts data that was encrypted with encryptData
 * @param encryptedData - The encrypted data object
 * @param password - Optional password used during encryption
 * @param config - Encryption configuration
 * @returns Promise resolving to DecryptionResult
 */
export async function decryptData(
  encryptedData: EncryptionResult,
  password?: string,
  config: EncryptionConfig = DEFAULT_ENCRYPTION_CONFIG
): Promise<DecryptionResult> {
  try {
    // Decode the encrypted components
    const ciphertext = base64ToArrayBuffer(encryptedData.ciphertext);
    const iv = base64ToArrayBuffer(encryptedData.iv);
    const salt = base64ToArrayBuffer(encryptedData.salt);
    
    // Create combined key
    const combinedKey = createCombinedKey(password);
    
    // Derive decryption key
    const decryptionKey = await deriveKeyFromPassword(combinedKey, salt, config);
    
    // Perform decryption
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: config.algorithm,
        iv: iv.buffer as ArrayBuffer,
      },
      decryptionKey,
      ciphertext.buffer as ArrayBuffer
    );
    
    // Convert decrypted bytes to string
    const plaintext = uint8ArrayToString(new Uint8Array(decryptedBuffer));
    
    // Verify integrity
    const computedChecksum = await computeSHA256Hash(plaintext);
    const integrityVerified = computedChecksum.slice(0, 16) === encryptedData.checksum;
    
    return {
      plaintext,
      success: true,
      integrityVerified,
    };
  } catch (error) {
    console.error('Decryption error:', error);
    return {
      plaintext: '',
      success: false,
      error: error instanceof Error ? error.message : 'Decryption failed',
      integrityVerified: false,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONVENIENCE FUNCTIONS FOR COMMON OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Encrypts a JSON object
 * @param data - The object to encrypt
 * @param password - Optional password
 * @returns Promise resolving to EncryptionResult
 */
export async function encryptJSON<T>(data: T, password?: string): Promise<EncryptionResult> {
  const jsonString = JSON.stringify(data);
  return encryptData(jsonString, password);
}

/**
 * Decrypts to a JSON object
 * @param encryptedData - The encrypted data
 * @param password - Optional password
 * @returns Promise resolving to the decrypted object or null
 */
export async function decryptJSON<T>(
  encryptedData: EncryptionResult,
  password?: string
): Promise<T | null> {
  const result = await decryptData(encryptedData, password);
  
  if (!result.success) {
    return null;
  }
  
  try {
    return JSON.parse(result.plaintext) as T;
  } catch {
    return null;
  }
}

/**
 * Encrypts sensitive string data (like passwords, API keys)
 * @param sensitiveData - The sensitive string to encrypt
 * @returns Promise resolving to encrypted string (serialized EncryptionResult)
 */
export async function encryptSensitiveString(sensitiveData: string): Promise<string> {
  const encrypted = await encryptData(sensitiveData);
  return JSON.stringify(encrypted);
}

/**
 * Decrypts a sensitive string
 * @param encryptedString - The encrypted string (serialized EncryptionResult)
 * @returns Promise resolving to decrypted string or null
 */
export async function decryptSensitiveString(encryptedString: string): Promise<string | null> {
  try {
    const encryptedData = JSON.parse(encryptedString) as EncryptionResult;
    const result = await decryptData(encryptedData);
    return result.success ? result.plaintext : null;
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PASSWORD HASHING (FOR AUTHENTICATION)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Hash configuration for password storage
 */
export interface PasswordHashResult {
  /** The derived hash */
  hash: string;
  /** Salt used for hashing */
  salt: string;
  /** Number of iterations */
  iterations: number;
  /** Algorithm version */
  version: string;
}

/**
 * Hashes a password for secure storage
 * @param password - The password to hash
 * @returns Promise resolving to PasswordHashResult
 */
export async function hashPassword(password: string): Promise<PasswordHashResult> {
  const salt = generateSalt(32);
  const iterations = 100000;
  
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    stringToUint8Array(password).buffer as ArrayBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations: iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    256
  );
  
  return {
    hash: arrayBufferToBase64(derivedBits),
    salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
    iterations,
    version: ENCRYPTION_VERSION,
  };
}

/**
 * Verifies a password against a stored hash
 * @param password - The password to verify
 * @param storedHash - The stored password hash result
 * @returns Promise resolving to boolean
 */
export async function verifyPassword(
  password: string,
  storedHash: PasswordHashResult
): Promise<boolean> {
  const salt = base64ToArrayBuffer(storedHash.salt);
  
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    stringToUint8Array(password).buffer as ArrayBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations: storedHash.iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    256
  );
  
  const computedHash = arrayBufferToBase64(derivedBits);
  return computedHash === storedHash.hash;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURE RANDOM GENERATION UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generates a secure random string suitable for tokens, session IDs, etc.
 * @param length - Desired length of the string
 * @param charset - Character set to use (default: alphanumeric)
 * @returns Random string
 */
export function generateSecureToken(
  length: number = 32,
  charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
): string {
  const randomBytes = generateSecureRandomBytes(length);
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += charset[randomBytes[i] % charset.length];
  }
  
  return result;
}

/**
 * Generates a secure OTP (One-Time Password)
 * @param length - Length of the OTP (default: 6)
 * @returns Numeric OTP string
 */
export function generateSecureOTP(length: number = 6): string {
  return generateSecureToken(length, '0123456789');
}

/**
 * Generates a secure API key
 * @param prefix - Optional prefix for the key
 * @returns API key string
 */
export function generateSecureAPIKey(prefix: string = 'vex'): string {
  const timestamp = Date.now().toString(36);
  const randomPart = generateSecureToken(24);
  return `${prefix}_${timestamp}_${randomPart}`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURE COMPARISON (TIMING-ATTACK RESISTANT)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Performs a constant-time string comparison to prevent timing attacks
 * @param a - First string
 * @param b - Second string
 * @returns Boolean indicating if strings are equal
 */
export function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATA SANITIZATION UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Sanitizes a string to prevent XSS attacks
 * @param input - The input string to sanitize
 * @returns Sanitized string
 */
export function sanitizeHTML(input: string): string {
  const htmlEntities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;',
  };
  
  return input.replace(/[&<>"'`=/]/g, char => htmlEntities[char] || char);
}

/**
 * Validates and sanitizes email addresses
 * @param email - The email to validate
 * @returns Sanitized email or null if invalid
 */
export function sanitizeEmail(email: string): string | null {
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  
  const trimmedEmail = email.trim().toLowerCase();
  
  if (emailRegex.test(trimmedEmail) && trimmedEmail.length <= 254) {
    return trimmedEmail;
  }
  
  return null;
}

/**
 * Validates password strength
 * @param password - The password to validate
 * @returns Object with validation results
 */
export function validatePasswordStrength(password: string): {
  isValid: boolean;
  score: number;
  feedback: string[];
} {
  const feedback: string[] = [];
  let score = 0;
  
  // Length check
  if (password.length >= 8) {
    score += 1;
  } else {
    feedback.push('Password must be at least 8 characters long');
  }
  
  if (password.length >= 12) {
    score += 1;
  }
  
  if (password.length >= 16) {
    score += 1;
  }
  
  // Uppercase check
  if (/[A-Z]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Add uppercase letters');
  }
  
  // Lowercase check
  if (/[a-z]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Add lowercase letters');
  }
  
  // Number check
  if (/[0-9]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Add numbers');
  }
  
  // Special character check
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Add special characters');
  }
  
  // Common patterns check
  const commonPatterns = [
    /^123/,
    /^abc/i,
    /password/i,
    /qwerty/i,
    /(.)\1{2,}/,
  ];
  
  for (const pattern of commonPatterns) {
    if (pattern.test(password)) {
      score -= 1;
      feedback.push('Avoid common patterns');
      break;
    }
  }
  
  return {
    isValid: score >= 4 && password.length >= 8,
    score: Math.max(0, Math.min(7, score)),
    feedback,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORT ALL UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

export const SecurityUtils = {
  // Encryption
  encryptData,
  decryptData,
  encryptJSON,
  decryptJSON,
  encryptSensitiveString,
  decryptSensitiveString,
  
  // Hashing
  computeSHA256Hash,
  computeSHA384Hash,
  computeSHA512Hash,
  computeHashWithMetadata,
  computeHMAC,
  verifyHMAC,
  
  // Password
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
};

export default SecurityUtils;
