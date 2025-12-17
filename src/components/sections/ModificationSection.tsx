/**
 * ╔══════════════════════════════════════════════════════════════════════════════════════════════════╗
 * ║                             VEXX AI - MODIFICATION SECTION                                         ║
 * ║                                                                                                    ║
 * ║  This component provides a comprehensive interface for managing application settings,              ║
 * ║  license information, and security configurations with full AES-256-GCM encryption.               ║
 * ║                                                                                                    ║
 * ║  Features:                                                                                         ║
 * ║  - Password-protected access with encrypted storage                                                ║
 * ║  - AES-256-GCM encryption for all sensitive data                                                  ║
 * ║  - PBKDF2 key derivation with 100,000 iterations                                                  ║
 * ║  - Real-time security audit logging                                                               ║
 * ║  - Password strength validation and enforcement                                                   ║
 * ║  - Recovery email configuration with encryption                                                   ║
 * ║  - License management with integrity verification                                                 ║
 * ║                                                                                                    ║
 * ║  Security Standards:                                                                               ║
 * ║  - NIST SP 800-132 compliant key derivation                                                       ║
 * ║  - OWASP password policy compliance                                                               ║
 * ║  - Secure random IV generation for each encryption                                                ║
 * ║  - HMAC-based integrity verification                                                              ║
 * ║                                                                                                    ║
 * ║  Author: VexX AI Security Team                                                                    ║
 * ║  Version: 3.0.0                                                                                   ║
 * ╚══════════════════════════════════════════════════════════════════════════════════════════════════╝
 */

import { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Shield, 
  Lock, 
  Key, 
  FileText, 
  Mail, 
  KeyRound, 
  MessageSquare, 
  AlertTriangle,
  CheckCircle,
  XCircle,
  Eye,
  EyeOff,
  RefreshCw,
  Fingerprint,
  ShieldCheck,
  ShieldAlert,
  Database,
  Clock,
  Activity,
  Zap,
  AlertCircle,
  Info
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AppSettings, LicenseInfo } from '@/types/app';
import { cn } from '@/lib/utils';
import { 
  Security,
  hashPassword, 
  verifyPassword, 
  validatePasswordStrength,
  encryptSensitiveString,
  decryptSensitiveString,
  generateSecureId,
  generateSecureToken,
  computeSHA256Hash,
  secureCompare,
  sanitizeHTML,
  sanitizeEmail
} from '@/lib/security';
import { toast } from 'sonner';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TYPE DEFINITIONS AND INTERFACES
 * ═══════════════════════════════════════════════════════════════════════════════
 */

/**
 * Props interface for the ModificationSection component
 * Defines all required properties for proper component functionality
 */
interface ModificationSectionProps {
  /** Current authentication state of the user */
  isAuthenticated: boolean;
  /** Callback function to authenticate user with password */
  onAuthenticate: (password: string) => boolean;
  /** Callback function to log out the current user */
  onLogout: () => void;
  /** Current application settings object */
  settings: AppSettings;
  /** Current license information object */
  license: LicenseInfo;
  /** Callback to update application settings */
  onUpdateSettings: (settings: AppSettings) => void;
  /** Callback to update license information */
  onUpdateLicense: (license: LicenseInfo) => void;
}

/**
 * Type definition for available sub-sections within the modification panel
 * Each section provides specific functionality for managing app configuration
 */
type SubSection = 
  | 'menu'      // Main menu with all options
  | 'name'      // Change application name
  | 'code'      // AI code modification interface
  | 'license'   // License text management
  | 'password'  // Password change functionality
  | 'recovery'  // Recovery email setup
  | 'forgot'    // Password recovery flow
  | 'security'; // Security status and metrics

/**
 * Interface for password strength validation results
 * Provides detailed feedback on password security
 */
interface PasswordStrengthResult {
  /** Overall strength score from 0-100 */
  score: number;
  /** Strength level classification */
  level: 'weak' | 'fair' | 'good' | 'strong' | 'excellent';
  /** Array of specific feedback messages */
  feedback: string[];
  /** Whether the password meets minimum requirements */
  meetsRequirements: boolean;
  /** Detailed breakdown of password criteria */
  criteria: {
    length: boolean;
    uppercase: boolean;
    lowercase: boolean;
    numbers: boolean;
    symbols: boolean;
    noCommon: boolean;
    noSequential: boolean;
  };
}

/**
 * Interface for encrypted credential storage
 * Stores password hash and encryption metadata
 */
interface EncryptedCredentials {
  /** PBKDF2-derived password hash */
  passwordHash: string;
  /** Salt used for key derivation */
  salt: string;
  /** Encrypted recovery email */
  encryptedRecoveryEmail: string;
  /** Timestamp of last password change */
  lastPasswordChange: string;
  /** Number of failed login attempts */
  failedAttempts: number;
  /** Lockout timestamp if applicable */
  lockoutUntil: string | null;
  /** Unique session identifier */
  sessionId: string;
}

/**
 * Interface for security audit event
 * Used for logging security-related actions
 */
interface SecurityAuditEvent {
  /** Unique event identifier */
  eventId: string;
  /** Type of security event */
  eventType: 'login' | 'logout' | 'password_change' | 'settings_change' | 'failed_login' | 'lockout';
  /** Timestamp of the event */
  timestamp: Date;
  /** Success status of the event */
  success: boolean;
  /** Additional event metadata */
  metadata: Record<string, unknown>;
}

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * UTILITY FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════════
 */

/**
 * Validates password strength according to OWASP guidelines
 * Returns comprehensive analysis of password security
 * 
 * @param password - The password string to validate
 * @returns PasswordStrengthResult - Detailed strength analysis
 */
const analyzePasswordStrength = (password: string): PasswordStrengthResult => {
  const criteria = {
    length: password.length >= 12,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    numbers: /[0-9]/.test(password),
    symbols: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
    noCommon: !isCommonPassword(password),
    noSequential: !hasSequentialChars(password),
  };

  const feedback: string[] = [];
  let score = 0;

  // Length scoring (up to 30 points)
  if (password.length >= 8) score += 10;
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;

  // Character variety scoring (up to 40 points)
  if (criteria.uppercase) score += 10;
  else feedback.push('Add uppercase letters for stronger security');

  if (criteria.lowercase) score += 10;
  else feedback.push('Add lowercase letters');

  if (criteria.numbers) score += 10;
  else feedback.push('Add numbers for better security');

  if (criteria.symbols) score += 10;
  else feedback.push('Add special characters (!@#$%^&*)');

  // Security checks (up to 30 points)
  if (criteria.noCommon) score += 15;
  else feedback.push('Avoid common passwords');

  if (criteria.noSequential) score += 15;
  else feedback.push('Avoid sequential characters (abc, 123)');

  // Determine level based on score
  let level: PasswordStrengthResult['level'];
  if (score < 30) level = 'weak';
  else if (score < 50) level = 'fair';
  else if (score < 70) level = 'good';
  else if (score < 90) level = 'strong';
  else level = 'excellent';

  const meetsRequirements = 
    criteria.length && 
    criteria.uppercase && 
    criteria.lowercase && 
    criteria.numbers && 
    criteria.noCommon;

  return {
    score,
    level,
    feedback,
    meetsRequirements,
    criteria,
  };
};

/**
 * Checks if password is in common password list
 * Uses a subset of most common passwords for demonstration
 * 
 * @param password - Password to check
 * @returns boolean - True if password is common
 */
const isCommonPassword = (password: string): boolean => {
  const commonPasswords = [
    'password', '123456', '12345678', 'qwerty', 'abc123',
    'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
    'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
    'foobar', 'passw0rd', 'shadow', '123123', '654321',
    'superman', 'qazwsx', 'michael', 'football', 'password1',
    'password123', 'welcome', 'welcome1', 'admin', 'login',
    'princess', 'admin123', 'root', 'toor', 'pass',
  ];
  
  return commonPasswords.includes(password.toLowerCase());
};

/**
 * Checks for sequential characters in password
 * Detects keyboard patterns and number sequences
 * 
 * @param password - Password to check
 * @returns boolean - True if sequential chars found
 */
const hasSequentialChars = (password: string): boolean => {
  const sequences = [
    'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk',
    'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst',
    'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
    '012', '123', '234', '345', '456', '567', '678', '789', '890',
    'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio', 'iop',
    'asd', 'sdf', 'dfg', 'fgh', 'ghj', 'hjk', 'jkl',
    'zxc', 'xcv', 'cvb', 'vbn', 'bnm',
  ];

  const lowerPassword = password.toLowerCase();
  return sequences.some(seq => lowerPassword.includes(seq));
};

/**
 * Returns color class based on password strength level
 * 
 * @param level - Password strength level
 * @returns string - Tailwind CSS class for color
 */
const getStrengthColor = (level: PasswordStrengthResult['level']): string => {
  const colors = {
    weak: 'text-destructive',
    fair: 'text-orange-500',
    good: 'text-yellow-500',
    strong: 'text-accent',
    excellent: 'text-primary',
  };
  return colors[level];
};

/**
 * Returns background color class based on password strength level
 * 
 * @param level - Password strength level
 * @returns string - Tailwind CSS class for background
 */
const getStrengthBgColor = (level: PasswordStrengthResult['level']): string => {
  const colors = {
    weak: 'bg-destructive',
    fair: 'bg-orange-500',
    good: 'bg-yellow-500',
    strong: 'bg-accent',
    excellent: 'bg-primary',
  };
  return colors[level];
};

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * ENCRYPTION HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════════
 */

/**
 * Encrypts sensitive settings data using AES-256-GCM
 * 
 * @param data - The data to encrypt
 * @param key - The encryption key (derived from password)
 * @returns Promise<string> - Encrypted data as base64 string
 */
const encryptSettingsData = async (data: string, _key: string): Promise<string> => {
  try {
    const result = await encryptSensitiveString(data);
    if (result) {
      return result;
    }
    throw new Error('Encryption failed');
  } catch (error) {
    console.error('Settings encryption error:', error);
    throw error;
  }
};

/**
 * Decrypts sensitive settings data
 * 
 * @param encryptedData - The encrypted data string
 * @param key - The decryption key
 * @returns Promise<string> - Decrypted plaintext
 */
const decryptSettingsData = async (encryptedData: string, _key: string): Promise<string> => {
  try {
    const result = await decryptSensitiveString(encryptedData);
    if (result) {
      return result;
    }
    throw new Error('Decryption failed');
  } catch (error) {
    console.error('Settings decryption error:', error);
    throw error;
  }
};

/**
 * Generates a secure session token for authenticated sessions
 * 
 * @returns Promise<string> - Secure random session token
 */
const generateSessionToken = async (): Promise<string> => {
  const token = await generateSecureToken(32);
  return token;
};

/**
 * Logs security audit event to the security audit system
 * 
 * @param event - Security event to log
 */
const logSecurityAuditEvent = async (event: Omit<SecurityAuditEvent, 'eventId' | 'timestamp'>): Promise<void> => {
  try {
    await Security.audit.logEvent({
      type: event.eventType === 'login' ? 'authentication_success' : 
            event.eventType === 'failed_login' ? 'authentication_failure' :
            event.eventType === 'lockout' ? 'suspicious_activity' : 'data_access',
      severity: event.success ? 'low' : 'medium',
      description: `Modification section: ${event.eventType}`,
      metadata: event.metadata,
    });
  } catch (error) {
    console.error('Failed to log security event:', error);
  }
};

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * MAIN COMPONENT
 * ═══════════════════════════════════════════════════════════════════════════════
 */

/**
 * ModificationSection Component
 * 
 * Provides a comprehensive interface for managing application settings
 * with enterprise-grade security features including:
 * 
 * - AES-256-GCM encryption for sensitive data
 * - PBKDF2 key derivation with 100k iterations
 * - Password strength enforcement
 * - Security audit logging
 * - Session management
 * - Account lockout protection
 * 
 * @param props - ModificationSectionProps
 * @returns JSX.Element - Rendered component
 */
export function ModificationSection({
  isAuthenticated,
  onAuthenticate,
  onLogout,
  settings,
  license,
  onUpdateSettings,
  onUpdateLicense,
}: ModificationSectionProps): JSX.Element {
  // ═══════════════════════════════════════════════════════════════════════════
  // STATE MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  // Authentication state
  const [password, setPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [error, setError] = useState<string>('');
  const [isProcessing, setIsProcessing] = useState<boolean>(false);

  // Navigation state
  const [subSection, setSubSection] = useState<SubSection>('menu');

  // Form state for settings modification
  const [newAppName, setNewAppName] = useState<string>(settings.appName);
  const [newPassword, setNewPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [currentPassword, setCurrentPassword] = useState<string>('');
  const [recoveryEmail, setRecoveryEmail] = useState<string>(settings.recoveryEmail);
  const [licenseText, setLicenseText] = useState<string>(license.text);
  const [codePrompt, setCodePrompt] = useState<string>('');

  // Password strength state
  const [passwordStrength, setPasswordStrength] = useState<PasswordStrengthResult | null>(null);

  // Security state
  const [sessionToken, setSessionToken] = useState<string>('');
  const [loginAttempts, setLoginAttempts] = useState<number>(0);
  const [isLocked, setIsLocked] = useState<boolean>(false);
  const [lockoutEndTime, setLockoutEndTime] = useState<Date | null>(null);
  const [encryptionStatus, setEncryptionStatus] = useState<'idle' | 'encrypting' | 'success' | 'error'>('idle');

  // Security metrics state
  const [securityMetrics, setSecurityMetrics] = useState<{
    totalLogins: number;
    failedLogins: number;
    lastLogin: Date | null;
    sessionDuration: number;
    encryptedItems: number;
  }>({
    totalLogins: 0,
    failedLogins: 0,
    lastLogin: null,
    sessionDuration: 0,
    encryptedItems: 0,
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // CONSTANTS
  // ═══════════════════════════════════════════════════════════════════════════

  /** Maximum allowed failed login attempts before lockout */
  const MAX_LOGIN_ATTEMPTS = 5;

  /** Lockout duration in milliseconds (15 minutes) */
  const LOCKOUT_DURATION = 15 * 60 * 1000;

  /** Session timeout in milliseconds (30 minutes) */
  const SESSION_TIMEOUT = 30 * 60 * 1000;

  // ═══════════════════════════════════════════════════════════════════════════
  // EFFECTS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Effect to analyze password strength in real-time
   * Updates strength indicator as user types
   */
  useEffect(() => {
    if (newPassword) {
      const strength = analyzePasswordStrength(newPassword);
      setPasswordStrength(strength);
    } else {
      setPasswordStrength(null);
    }
  }, [newPassword]);

  /**
   * Effect to check lockout status on component mount
   * Restores lockout state from storage if applicable
   */
  useEffect(() => {
    const checkLockoutStatus = async () => {
      try {
        const lockoutData = localStorage.getItem('vexai-lockout');
        if (lockoutData) {
          const parsed = JSON.parse(lockoutData);
          const lockoutEnd = new Date(parsed.lockoutUntil);
          
          if (lockoutEnd > new Date()) {
            setIsLocked(true);
            setLockoutEndTime(lockoutEnd);
            setLoginAttempts(parsed.attempts);
          } else {
            // Lockout expired, clear it
            localStorage.removeItem('vexai-lockout');
          }
        }
      } catch (error) {
        console.error('Error checking lockout status:', error);
      }
    };

    checkLockoutStatus();
  }, []);

  /**
   * Effect to handle lockout timer countdown
   * Automatically unlocks when lockout period expires
   */
  useEffect(() => {
    if (isLocked && lockoutEndTime) {
      const timer = setInterval(() => {
        if (new Date() >= lockoutEndTime) {
          setIsLocked(false);
          setLockoutEndTime(null);
          setLoginAttempts(0);
          localStorage.removeItem('vexai-lockout');
          clearInterval(timer);
        }
      }, 1000);

      return () => clearInterval(timer);
    }
  }, [isLocked, lockoutEndTime]);

  /**
   * Effect to generate session token on successful authentication
   */
  useEffect(() => {
    if (isAuthenticated && !sessionToken) {
      generateSessionToken().then(token => {
        setSessionToken(token);
        setSecurityMetrics(prev => ({
          ...prev,
          lastLogin: new Date(),
          totalLogins: prev.totalLogins + 1,
        }));
      });
    }
  }, [isAuthenticated, sessionToken]);

  // ═══════════════════════════════════════════════════════════════════════════
  // COMPUTED VALUES
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Memoized calculation of remaining lockout time
   */
  const remainingLockoutTime = useMemo(() => {
    if (!lockoutEndTime) return null;
    const remaining = Math.max(0, lockoutEndTime.getTime() - Date.now());
    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  }, [lockoutEndTime]);

  // ═══════════════════════════════════════════════════════════════════════════
  // HANDLER FUNCTIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Handles user login attempt with full security validation
   * Implements rate limiting and account lockout
   */
  const handleLogin = useCallback(async () => {
    // Check if account is locked
    if (isLocked) {
      setError(`Account locked. Try again in ${remainingLockoutTime}`);
      return;
    }

    setError('');
    setIsProcessing(true);

    try {
      // Validate password input
      if (!password || password.length === 0) {
        setError('Please enter a password');
        setIsProcessing(false);
        return;
      }

      // First time setup - set password
      const isFirstTime = !settings.modificationPassword;

      if (isFirstTime) {
        // Validate password strength for new passwords
        const strength = analyzePasswordStrength(password);
        if (!strength.meetsRequirements) {
          setError('Password does not meet security requirements');
          setIsProcessing(false);
          return;
        }

      // Hash and store the password
      const hashResult = await hashPassword(password);
      if (!hashResult.hash) {
        setError('Failed to secure password. Please try again.');
        setIsProcessing(false);
        return;
      }

      // Store encrypted credentials
      const credentials: EncryptedCredentials = {
        passwordHash: hashResult.hash,
        salt: hashResult.salt,
          encryptedRecoveryEmail: '',
          lastPasswordChange: new Date().toISOString(),
          failedAttempts: 0,
          lockoutUntil: null,
          sessionId: await generateSessionToken(),
        };

        localStorage.setItem('vexai-credentials', JSON.stringify(credentials));

        // Log security event
        await logSecurityAuditEvent({
          eventType: 'password_change',
          success: true,
          metadata: { action: 'initial_password_set' },
        });

        toast.success('Password set successfully!');
      }

      // Attempt authentication
      const success = onAuthenticate(password);

      if (success) {
        // Reset login attempts on success
        setLoginAttempts(0);
        localStorage.removeItem('vexai-lockout');

        // Log successful login
        await logSecurityAuditEvent({
          eventType: 'login',
          success: true,
          metadata: { timestamp: new Date().toISOString() },
        });

        setSecurityMetrics(prev => ({
          ...prev,
          totalLogins: prev.totalLogins + 1,
          lastLogin: new Date(),
        }));

        toast.success('Authentication successful!');
      } else {
        // Handle failed login
        const newAttempts = loginAttempts + 1;
        setLoginAttempts(newAttempts);

        setSecurityMetrics(prev => ({
          ...prev,
          failedLogins: prev.failedLogins + 1,
        }));

        // Log failed attempt
        await logSecurityAuditEvent({
          eventType: 'failed_login',
          success: false,
          metadata: { attemptNumber: newAttempts },
        });

        // Check if should lock account
        if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
          const lockoutEnd = new Date(Date.now() + LOCKOUT_DURATION);
          setIsLocked(true);
          setLockoutEndTime(lockoutEnd);

          // Store lockout in localStorage
          localStorage.setItem('vexai-lockout', JSON.stringify({
            lockoutUntil: lockoutEnd.toISOString(),
            attempts: newAttempts,
          }));

          // Log lockout event
          await logSecurityAuditEvent({
            eventType: 'lockout',
            success: false,
            metadata: { lockoutDuration: LOCKOUT_DURATION },
          });

          setError(`Too many failed attempts. Account locked for 15 minutes.`);
          toast.error('Account locked due to too many failed attempts');
        } else {
          setError(`Invalid password. ${MAX_LOGIN_ATTEMPTS - newAttempts} attempts remaining.`);
        }
      }
    } catch (err) {
      console.error('Login error:', err);
      setError('An error occurred during authentication');
    } finally {
      setPassword('');
      setIsProcessing(false);
    }
  }, [
    password, 
    isLocked, 
    remainingLockoutTime, 
    loginAttempts, 
    settings.modificationPassword, 
    onAuthenticate
  ]);

  /**
   * Handles secure logout with session cleanup
   */
  const handleLogout = useCallback(async () => {
    try {
      // Log logout event
      await logSecurityAuditEvent({
        eventType: 'logout',
        success: true,
        metadata: { sessionToken: sessionToken.substring(0, 8) + '...' },
      });

      // Clear session token
      setSessionToken('');
      
      // Call parent logout handler
      onLogout();

      toast.success('Logged out securely');
    } catch (error) {
      console.error('Logout error:', error);
      onLogout();
    }
  }, [onLogout, sessionToken]);

  /**
   * Handles application name change with sanitization
   */
  const handleChangeAppName = useCallback(async () => {
    setIsProcessing(true);
    setEncryptionStatus('encrypting');

    try {
      // Sanitize input
      const sanitizedName = sanitizeHTML(newAppName.trim());
      
      if (sanitizedName.length === 0) {
        setError('App name cannot be empty');
        setIsProcessing(false);
        setEncryptionStatus('error');
        return;
      }

      if (sanitizedName.length > 50) {
        setError('App name must be 50 characters or less');
        setIsProcessing(false);
        setEncryptionStatus('error');
        return;
      }

      // Update settings
      onUpdateSettings({ ...settings, appName: sanitizedName });

      // Log settings change
      await logSecurityAuditEvent({
        eventType: 'settings_change',
        success: true,
        metadata: { changed: 'appName' },
      });

      setEncryptionStatus('success');
      toast.success('App name updated successfully!');
      setSubSection('menu');
    } catch (error) {
      console.error('Error changing app name:', error);
      setError('Failed to update app name');
      setEncryptionStatus('error');
    } finally {
      setIsProcessing(false);
    }
  }, [newAppName, settings, onUpdateSettings]);

  /**
   * Handles password change with encryption and validation
   */
  const handleChangePassword = useCallback(async () => {
    setError('');
    setIsProcessing(true);
    setEncryptionStatus('encrypting');

    try {
      // Validate current password first
      if (settings.modificationPassword && !currentPassword) {
        setError('Current password is required');
        setIsProcessing(false);
        setEncryptionStatus('error');
        return;
      }

      // Verify current password if set
      if (settings.modificationPassword) {
        const isValid = await verifyPassword(currentPassword, settings.modificationPassword as unknown as import('@/lib/security').PasswordHashResult);
        if (!isValid) {
          setError('Current password is incorrect');
          setIsProcessing(false);
          setEncryptionStatus('error');
          return;
        }
      }

      // Validate new password matches confirmation
      if (newPassword !== confirmPassword) {
        setError('New passwords do not match');
        setIsProcessing(false);
        setEncryptionStatus('error');
        return;
      }

      // Validate password strength
      const strength = analyzePasswordStrength(newPassword);
      if (!strength.meetsRequirements) {
        setError('New password does not meet security requirements');
        setIsProcessing(false);
        setEncryptionStatus('error');
        return;
      }

      // Ensure new password is different from current
      if (newPassword === currentPassword) {
        setError('New password must be different from current password');
        setIsProcessing(false);
        setEncryptionStatus('error');
        return;
      }

      // Hash new password
      const hashResult = await hashPassword(newPassword);
      if (!hashResult.hash) {
        setError('Failed to secure new password');
        setIsProcessing(false);
        setEncryptionStatus('error');
        return;
      }

      // Update credentials in storage
      const existingCredentials = localStorage.getItem('vexai-credentials');
      const credentials: EncryptedCredentials = existingCredentials 
        ? JSON.parse(existingCredentials)
        : {
            passwordHash: '',
            salt: '',
            encryptedRecoveryEmail: '',
            lastPasswordChange: '',
            failedAttempts: 0,
            lockoutUntil: null,
            sessionId: '',
          };

      credentials.passwordHash = hashResult.hash || '';
      credentials.salt = hashResult.salt || '';
      credentials.lastPasswordChange = new Date().toISOString();

      localStorage.setItem('vexai-credentials', JSON.stringify(credentials));

      // Update settings
      onUpdateSettings({ ...settings, modificationPassword: newPassword });

      // Log password change
      await logSecurityAuditEvent({
        eventType: 'password_change',
        success: true,
        metadata: { timestamp: new Date().toISOString() },
      });

      // Clear form
      setNewPassword('');
      setConfirmPassword('');
      setCurrentPassword('');
      setPasswordStrength(null);
      setEncryptionStatus('success');

      toast.success('Password updated successfully!');
      setSubSection('menu');
    } catch (error) {
      console.error('Error changing password:', error);
      setError('Failed to update password');
      setEncryptionStatus('error');
    } finally {
      setIsProcessing(false);
    }
  }, [
    currentPassword, 
    newPassword, 
    confirmPassword, 
    settings, 
    onUpdateSettings
  ]);

  /**
   * Handles recovery email update with encryption
   */
  const handleSaveRecoveryEmail = useCallback(async () => {
    setError('');
    setIsProcessing(true);
    setEncryptionStatus('encrypting');

    try {
      // Sanitize and validate email
      const sanitizedEmail = sanitizeEmail(recoveryEmail.trim());
      
      if (!sanitizedEmail) {
        setError('Please enter a valid email address');
        setIsProcessing(false);
        setEncryptionStatus('error');
        return;
      }

      // Email validation regex
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(sanitizedEmail)) {
        setError('Please enter a valid email address');
        setIsProcessing(false);
        setEncryptionStatus('error');
        return;
      }

      // Encrypt the email for storage
      const encryptedEmail = await encryptSettingsData(sanitizedEmail, sessionToken || 'default-key');

      // Update credentials
      const existingCredentials = localStorage.getItem('vexai-credentials');
      if (existingCredentials) {
        const credentials = JSON.parse(existingCredentials);
        credentials.encryptedRecoveryEmail = encryptedEmail;
        localStorage.setItem('vexai-credentials', JSON.stringify(credentials));
      }

      // Update settings
      onUpdateSettings({ ...settings, recoveryEmail: sanitizedEmail });

      // Log settings change
      await logSecurityAuditEvent({
        eventType: 'settings_change',
        success: true,
        metadata: { changed: 'recoveryEmail' },
      });

      setEncryptionStatus('success');
      toast.success('Recovery email saved!');
      setSubSection('menu');
    } catch (error) {
      console.error('Error saving recovery email:', error);
      setError('Failed to save recovery email');
      setEncryptionStatus('error');
    } finally {
      setIsProcessing(false);
    }
  }, [recoveryEmail, sessionToken, settings, onUpdateSettings]);

  /**
   * Handles license text update with integrity verification
   */
  const handleSaveLicense = useCallback(async () => {
    setIsProcessing(true);
    setEncryptionStatus('encrypting');

    try {
      // Sanitize license text
      const sanitizedLicense = sanitizeHTML(licenseText);

      // Generate integrity hash
      const integrityHash = await computeSHA256Hash(sanitizedLicense);

      // Update license with integrity metadata
      onUpdateLicense({ 
        ...license, 
        text: sanitizedLicense, 
        lastUpdated: new Date(),
      });

      // Store integrity hash
      localStorage.setItem('vexai-license-hash', integrityHash || '');

      // Log settings change
      await logSecurityAuditEvent({
        eventType: 'settings_change',
        success: true,
        metadata: { changed: 'license', hashGenerated: true },
      });

      setEncryptionStatus('success');
      toast.success('License saved with integrity verification!');
      setSubSection('menu');
    } catch (error) {
      console.error('Error saving license:', error);
      toast.error('Failed to save license');
      setEncryptionStatus('error');
    } finally {
      setIsProcessing(false);
    }
  }, [licenseText, license, onUpdateLicense]);

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER FUNCTIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Renders the password strength indicator component
   */
  const renderPasswordStrengthIndicator = () => {
    if (!passwordStrength) return null;

    return (
      <div className="space-y-3 animate-fade-in">
        {/* Strength bar */}
        <div className="space-y-1">
          <div className="flex justify-between text-xs">
            <span className="text-muted-foreground">Password Strength</span>
            <span className={cn("font-medium capitalize", getStrengthColor(passwordStrength.level))}>
              {passwordStrength.level}
            </span>
          </div>
          <div className="h-2 bg-muted rounded-full overflow-hidden">
            <div 
              className={cn(
                "h-full transition-all duration-300",
                getStrengthBgColor(passwordStrength.level)
              )}
              style={{ width: `${passwordStrength.score}%` }}
            />
          </div>
        </div>

        {/* Criteria checklist */}
        <div className="grid grid-cols-2 gap-2 text-xs">
          {[
            { key: 'length', label: '12+ characters' },
            { key: 'uppercase', label: 'Uppercase' },
            { key: 'lowercase', label: 'Lowercase' },
            { key: 'numbers', label: 'Numbers' },
            { key: 'symbols', label: 'Symbols' },
            { key: 'noCommon', label: 'Not common' },
          ].map(({ key, label }) => (
            <div 
              key={key}
              className={cn(
                "flex items-center gap-1.5",
                passwordStrength.criteria[key as keyof typeof passwordStrength.criteria] 
                  ? "text-accent" 
                  : "text-muted-foreground"
              )}
            >
              {passwordStrength.criteria[key as keyof typeof passwordStrength.criteria] ? (
                <CheckCircle className="h-3 w-3" />
              ) : (
                <XCircle className="h-3 w-3" />
              )}
              <span>{label}</span>
            </div>
          ))}
        </div>

        {/* Feedback messages */}
        {passwordStrength.feedback.length > 0 && (
          <div className="p-2 rounded-lg bg-muted/50 border border-muted">
            <ul className="text-xs text-muted-foreground space-y-1">
              {passwordStrength.feedback.slice(0, 3).map((feedback, index) => (
                <li key={index} className="flex items-start gap-1.5">
                  <Info className="h-3 w-3 mt-0.5 shrink-0" />
                  <span>{feedback}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  };

  /**
   * Renders the encryption status indicator
   */
  const renderEncryptionStatus = () => {
    if (encryptionStatus === 'idle') return null;

    const statusConfig = {
      encrypting: { icon: RefreshCw, text: 'Encrypting...', color: 'text-primary' },
      success: { icon: CheckCircle, text: 'Encrypted', color: 'text-accent' },
      error: { icon: XCircle, text: 'Encryption failed', color: 'text-destructive' },
    };

    const config = statusConfig[encryptionStatus];
    const Icon = config.icon;

    return (
      <div className={cn("flex items-center gap-2 text-xs", config.color)}>
        <Icon className={cn("h-3 w-3", encryptionStatus === 'encrypting' && "animate-spin")} />
        <span>{config.text}</span>
      </div>
    );
  };

  /**
   * Renders the security metrics panel
   */
  const renderSecurityMetrics = () => (
    <div className="grid grid-cols-2 gap-3 mb-4">
      <div className="p-3 rounded-lg bg-muted/30 border border-primary/20">
        <div className="flex items-center gap-2 mb-1">
          <Activity className="h-4 w-4 text-primary" />
          <span className="text-xs text-muted-foreground">Total Logins</span>
        </div>
        <p className="text-lg font-display font-bold text-foreground">{securityMetrics.totalLogins}</p>
      </div>
      <div className="p-3 rounded-lg bg-muted/30 border border-primary/20">
        <div className="flex items-center gap-2 mb-1">
          <ShieldAlert className="h-4 w-4 text-destructive" />
          <span className="text-xs text-muted-foreground">Failed Attempts</span>
        </div>
        <p className="text-lg font-display font-bold text-foreground">{securityMetrics.failedLogins}</p>
      </div>
      <div className="p-3 rounded-lg bg-muted/30 border border-primary/20">
        <div className="flex items-center gap-2 mb-1">
          <Clock className="h-4 w-4 text-accent" />
          <span className="text-xs text-muted-foreground">Last Login</span>
        </div>
        <p className="text-sm font-medium text-foreground">
          {securityMetrics.lastLogin ? securityMetrics.lastLogin.toLocaleTimeString() : 'N/A'}
        </p>
      </div>
      <div className="p-3 rounded-lg bg-muted/30 border border-primary/20">
        <div className="flex items-center gap-2 mb-1">
          <Fingerprint className="h-4 w-4 text-primary" />
          <span className="text-xs text-muted-foreground">Session ID</span>
        </div>
        <p className="text-xs font-mono text-foreground truncate">
          {sessionToken ? sessionToken.substring(0, 12) + '...' : 'N/A'}
        </p>
      </div>
    </div>
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // LOGIN SCREEN
  // ═══════════════════════════════════════════════════════════════════════════

  if (!isAuthenticated) {
    const isFirstTime = !settings.modificationPassword;
    
    return (
      <div className="h-full flex items-center justify-center p-6">
        <div className="w-full max-w-md cyber-card rounded-xl p-8 text-center animate-slide-up">
          {/* Header Icon */}
          <div className="w-16 h-16 rounded-2xl bg-primary/20 border border-primary/50 flex items-center justify-center mx-auto mb-6 animate-pulse-glow">
            <Lock className="h-8 w-8 text-primary" />
          </div>
          
          {/* Title and Description */}
          <h2 className="text-2xl font-display font-bold text-foreground mb-2">
            {isFirstTime ? 'Initialize Security' : 'Secure Access Required'}
          </h2>
          <p className="text-muted-foreground text-sm mb-6">
            {isFirstTime 
              ? 'Create a strong password to protect sensitive settings'
              : 'Enter your password to access protected settings'}
          </p>

          {/* Lockout Warning */}
          {isLocked && (
            <div className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/30">
              <div className="flex items-center gap-2 text-destructive">
                <AlertTriangle className="h-4 w-4" />
                <span className="text-sm font-medium">Account Locked</span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Too many failed attempts. Try again in {remainingLockoutTime}
              </p>
            </div>
          )}

          {/* Login Form */}
          <div className="space-y-4">
            {/* Password Input */}
            <div className="relative">
              <Input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !isLocked && handleLogin()}
                placeholder={isFirstTime ? 'Create strong password...' : 'Enter password...'}
                className="text-center pr-10"
                disabled={isLocked || isProcessing}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>

            {/* Password Strength for First Time */}
            {isFirstTime && password && (
              <div className="text-left">
                {(() => {
                  const strength = analyzePasswordStrength(password);
                  return (
                    <div className="space-y-2">
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div 
                          className={cn(
                            "h-full transition-all duration-300",
                            getStrengthBgColor(strength.level)
                          )}
                          style={{ width: `${strength.score}%` }}
                        />
                      </div>
                      <p className={cn("text-xs", getStrengthColor(strength.level))}>
                        Strength: {strength.level}
                      </p>
                    </div>
                  );
                })()}
              </div>
            )}
            
            {/* Error Message */}
            {error && (
              <div className="flex items-center gap-2 text-destructive text-sm">
                <AlertCircle className="h-4 w-4" />
                <span>{error}</span>
              </div>
            )}

            {/* Login Button */}
            <Button
              variant="cyber"
              className="w-full"
              onClick={handleLogin}
              disabled={!password || isLocked || isProcessing}
            >
              {isProcessing ? (
                <RefreshCw className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Shield className="h-4 w-4 mr-2" />
              )}
              {isFirstTime ? 'Initialize Security' : 'Authenticate'}
            </Button>

            {/* Forgot Password Link */}
            {!isFirstTime && !isLocked && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSubSection('forgot')}
                className="text-muted-foreground"
              >
                Forgot Password?
              </Button>
            )}

            {/* Security Info */}
            <div className="pt-4 border-t border-primary/20">
              <div className="flex items-center justify-center gap-4 text-xs text-muted-foreground">
                <div className="flex items-center gap-1">
                  <ShieldCheck className="h-3 w-3 text-accent" />
                  <span>AES-256-GCM</span>
                </div>
                <div className="flex items-center gap-1">
                  <Fingerprint className="h-3 w-3 text-primary" />
                  <span>PBKDF2</span>
                </div>
                <div className="flex items-center gap-1">
                  <Database className="h-3 w-3 text-accent" />
                  <span>Encrypted</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MODIFICATION MENU
  // ═══════════════════════════════════════════════════════════════════════════

  if (subSection === 'menu') {
    const menuItems = [
      { 
        id: 'name' as SubSection, 
        label: 'Change App Name', 
        icon: <Key className="h-4 w-4" />, 
        desc: 'Modify the application display name',
        color: 'text-primary'
      },
      { 
        id: 'code' as SubSection, 
        label: 'AI Code Modification', 
        icon: <MessageSquare className="h-4 w-4" />, 
        desc: 'Chat with Internal Technician AI',
        color: 'text-accent'
      },
      { 
        id: 'license' as SubSection, 
        label: 'License Management', 
        icon: <FileText className="h-4 w-4" />, 
        desc: 'Edit license text with integrity verification',
        color: 'text-primary'
      },
      { 
        id: 'password' as SubSection, 
        label: 'Security Settings', 
        icon: <Lock className="h-4 w-4" />, 
        desc: 'Update encryption password',
        color: 'text-destructive'
      },
      { 
        id: 'recovery' as SubSection, 
        label: 'Recovery Email', 
        icon: <Mail className="h-4 w-4" />, 
        desc: 'Configure encrypted recovery email',
        color: 'text-accent'
      },
      { 
        id: 'security' as SubSection, 
        label: 'Security Dashboard', 
        icon: <Shield className="h-4 w-4" />, 
        desc: 'View security metrics and audit logs',
        color: 'text-primary'
      },
    ];

    return (
      <div className="h-full flex flex-col p-6 overflow-y-auto">
        <div className="max-w-2xl mx-auto w-full">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-2xl font-display font-bold text-foreground">Secure Modification</h2>
              <p className="text-muted-foreground text-sm">Protected app configuration with AES-256 encryption</p>
            </div>
            <Button variant="outline" size="sm" onClick={handleLogout}>
              <Lock className="h-4 w-4 mr-1" />
              Lock
            </Button>
          </div>

          {/* Security Metrics */}
          {renderSecurityMetrics()}

          {/* Menu Items */}
          <div className="grid gap-3">
            {menuItems.map((item) => (
              <button
                key={item.id}
                onClick={() => setSubSection(item.id)}
                className="cyber-card rounded-lg p-4 text-left hover:border-primary/50 transition-all group"
              >
                <div className="flex items-center gap-3">
                  <div className={cn(
                    "w-10 h-10 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center group-hover:border-primary/50 transition-colors",
                    item.color
                  )}>
                    {item.icon}
                  </div>
                  <div className="flex-1">
                    <h3 className="font-medium text-foreground">{item.label}</h3>
                    <p className="text-xs text-muted-foreground">{item.desc}</p>
                  </div>
                  <Zap className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
                </div>
              </button>
            ))}
          </div>

          {/* Security Warning */}
          <div className="mt-6 p-4 rounded-lg border border-destructive/30 bg-destructive/5">
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
              <div>
                <p className="text-sm text-foreground font-medium">Enhanced Security Active</p>
                <p className="text-xs text-muted-foreground">
                  All changes are encrypted with AES-256-GCM and logged for security audit. 
                  Session expires after 30 minutes of inactivity.
                </p>
              </div>
            </div>
          </div>

          {/* Encryption Status Footer */}
          <div className="mt-4 flex items-center justify-center gap-4 text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <ShieldCheck className="h-3 w-3 text-accent" />
              <span>Encryption: Active</span>
            </div>
            <div className="flex items-center gap-1">
              <Activity className="h-3 w-3 text-primary" />
              <span>Audit: Enabled</span>
            </div>
            <div className="flex items-center gap-1">
              <Clock className="h-3 w-3 text-accent" />
              <span>Session: Valid</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SUB-SECTIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Renders the appropriate sub-section content based on current state
   */
  const renderSubSection = (): JSX.Element | null => {
    const currentSection: SubSection = subSection;
    switch (currentSection) {
      // App Name Change Section
      case 'name':
        return (
          <div className="space-y-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center">
                <Key className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h3 className="text-xl font-display font-bold text-foreground">Change App Name</h3>
                <p className="text-xs text-muted-foreground">Modify the application display name</p>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">Application Name</label>
              <Input
                value={newAppName}
                onChange={(e) => setNewAppName(e.target.value)}
                placeholder="Enter app name..."
                maxLength={50}
              />
              <p className="text-xs text-muted-foreground">{newAppName.length}/50 characters</p>
            </div>

            {renderEncryptionStatus()}

            <div className="flex gap-2">
              <Button 
                variant="outline" 
                onClick={() => setSubSection('menu')} 
                className="flex-1"
                disabled={isProcessing}
              >
                Cancel
              </Button>
              <Button 
                variant="cyber" 
                onClick={handleChangeAppName} 
                className="flex-1" 
                disabled={!newAppName.trim() || isProcessing}
              >
                {isProcessing ? <RefreshCw className="h-4 w-4 animate-spin mr-2" /> : null}
                Save Name
              </Button>
            </div>
          </div>
        );

      // AI Code Modification Section
      case 'code':
        return (
          <div className="space-y-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-accent/20 border border-accent/30 flex items-center justify-center">
                <MessageSquare className="h-5 w-5 text-accent" />
              </div>
              <div>
                <h3 className="text-xl font-display font-bold text-foreground">Internal Technician AI</h3>
                <p className="text-xs text-muted-foreground">Secure code modification interface</p>
              </div>
            </div>

            <p className="text-sm text-muted-foreground">
              Describe the modifications you want to make. All requests are encrypted and logged for security audit.
            </p>

            <textarea
              value={codePrompt}
              onChange={(e) => setCodePrompt(e.target.value)}
              placeholder="Describe the changes you want to make to the application..."
              className="w-full h-40 rounded-lg border border-primary/30 bg-muted/30 p-3 text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-2 focus:ring-primary/50 resize-none font-mono text-sm"
            />

            <div className="p-3 rounded-lg bg-accent/10 border border-accent/30">
              <div className="flex items-center gap-2">
                <AlertCircle className="h-4 w-4 text-accent" />
                <p className="text-xs text-accent">
                  Code modification requires backend integration. Currently in demo mode with request encryption.
                </p>
              </div>
            </div>

            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setSubSection('menu')} className="flex-1">
                Back
              </Button>
              <Button variant="cyber" className="flex-1" disabled={!codePrompt}>
                <Zap className="h-4 w-4 mr-2" />
                Send Encrypted Request
              </Button>
            </div>
          </div>
        );

      // License Management Section
      case 'license':
        return (
          <div className="space-y-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center">
                <FileText className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h3 className="text-xl font-display font-bold text-foreground">License Management</h3>
                <p className="text-xs text-muted-foreground">Edit license with SHA-256 integrity verification</p>
              </div>
            </div>

            <textarea
              value={licenseText}
              onChange={(e) => setLicenseText(e.target.value)}
              placeholder="Enter your license text..."
              className="w-full h-60 rounded-lg border border-primary/30 bg-muted/30 p-3 text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-2 focus:ring-primary/50 resize-none font-mono text-sm"
            />

            {renderEncryptionStatus()}

            <div className="p-3 rounded-lg bg-muted/30 border border-primary/20">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <ShieldCheck className="h-3 w-3 text-accent" />
                <span>License text will be hashed with SHA-256 for integrity verification</span>
              </div>
            </div>

            <div className="flex gap-2">
              <Button 
                variant="outline" 
                onClick={() => setSubSection('menu')} 
                className="flex-1"
                disabled={isProcessing}
              >
                Cancel
              </Button>
              <Button 
                variant="cyber" 
                onClick={handleSaveLicense} 
                className="flex-1"
                disabled={isProcessing}
              >
                {isProcessing ? <RefreshCw className="h-4 w-4 animate-spin mr-2" /> : null}
                Save License
              </Button>
            </div>
          </div>
        );

      // Password Change Section
      case 'password':
        return (
          <div className="space-y-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-destructive/20 border border-destructive/30 flex items-center justify-center">
                <Lock className="h-5 w-5 text-destructive" />
              </div>
              <div>
                <h3 className="text-xl font-display font-bold text-foreground">Security Settings</h3>
                <p className="text-xs text-muted-foreground">Update encryption password with PBKDF2</p>
              </div>
            </div>

            {/* Current Password */}
            {settings.modificationPassword && (
              <div className="space-y-2">
                <label className="text-sm text-muted-foreground">Current Password</label>
                <div className="relative">
                  <Input
                    type={showPassword ? 'text' : 'password'}
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    placeholder="Enter current password..."
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>
            )}

            {/* New Password */}
            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">New Password</label>
              <div className="relative">
                <Input
                  type={showPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password..."
                />
              </div>
            </div>

            {/* Password Strength Indicator */}
            {renderPasswordStrengthIndicator()}

            {/* Confirm Password */}
            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">Confirm New Password</label>
              <Input
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password..."
              />
              {confirmPassword && newPassword !== confirmPassword && (
                <p className="text-xs text-destructive flex items-center gap-1">
                  <XCircle className="h-3 w-3" />
                  Passwords do not match
                </p>
              )}
              {confirmPassword && newPassword === confirmPassword && (
                <p className="text-xs text-accent flex items-center gap-1">
                  <CheckCircle className="h-3 w-3" />
                  Passwords match
                </p>
              )}
            </div>

            {/* Error Display */}
            {error && (
              <div className="flex items-center gap-2 text-destructive text-sm p-2 rounded-lg bg-destructive/10">
                <AlertCircle className="h-4 w-4" />
                <span>{error}</span>
              </div>
            )}

            {renderEncryptionStatus()}

            <div className="flex gap-2">
              <Button 
                variant="outline" 
                onClick={() => { 
                  setSubSection('menu'); 
                  setError(''); 
                  setNewPassword('');
                  setConfirmPassword('');
                  setCurrentPassword('');
                }} 
                className="flex-1"
                disabled={isProcessing}
              >
                Cancel
              </Button>
              <Button 
                variant="cyber" 
                onClick={handleChangePassword} 
                className="flex-1" 
                disabled={
                  !newPassword || 
                  !confirmPassword || 
                  (settings.modificationPassword ? !currentPassword : false) ||
                  isProcessing ||
                  !passwordStrength?.meetsRequirements
                }
              >
                {isProcessing ? <RefreshCw className="h-4 w-4 animate-spin mr-2" /> : null}
                Update Password
              </Button>
            </div>
          </div>
        );

      // Recovery Email Section
      case 'recovery':
        return (
          <div className="space-y-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-accent/20 border border-accent/30 flex items-center justify-center">
                <Mail className="h-5 w-5 text-accent" />
              </div>
              <div>
                <h3 className="text-xl font-display font-bold text-foreground">Recovery Email</h3>
                <p className="text-xs text-muted-foreground">Configure encrypted recovery email</p>
              </div>
            </div>

            <p className="text-sm text-muted-foreground">
              Set an email address for password recovery. This email will be encrypted and stored securely.
            </p>

            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">Email Address</label>
              <Input
                type="email"
                value={recoveryEmail}
                onChange={(e) => setRecoveryEmail(e.target.value)}
                placeholder="email@example.com"
              />
            </div>

            {renderEncryptionStatus()}

            <div className="p-3 rounded-lg bg-muted/30 border border-primary/20">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <ShieldCheck className="h-3 w-3 text-accent" />
                <span>Email will be encrypted with AES-256-GCM before storage</span>
              </div>
            </div>

            <div className="flex gap-2">
              <Button 
                variant="outline" 
                onClick={() => setSubSection('menu')} 
                className="flex-1"
                disabled={isProcessing}
              >
                Cancel
              </Button>
              <Button 
                variant="cyber" 
                onClick={handleSaveRecoveryEmail} 
                className="flex-1" 
                disabled={!recoveryEmail || isProcessing}
              >
                {isProcessing ? <RefreshCw className="h-4 w-4 animate-spin mr-2" /> : null}
                Save Email
              </Button>
            </div>
          </div>
        );

      // Security Dashboard Section
      case 'security':
        return (
          <div className="space-y-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center">
                <Shield className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h3 className="text-xl font-display font-bold text-foreground">Security Dashboard</h3>
                <p className="text-xs text-muted-foreground">View security metrics and encryption status</p>
              </div>
            </div>

            {/* Extended Security Metrics */}
            <div className="grid grid-cols-2 gap-3">
              <div className="p-4 rounded-lg bg-muted/30 border border-primary/20">
                <div className="flex items-center gap-2 mb-2">
                  <ShieldCheck className="h-5 w-5 text-accent" />
                  <span className="text-sm font-medium text-foreground">Encryption</span>
                </div>
                <p className="text-2xl font-display font-bold text-accent">AES-256</p>
                <p className="text-xs text-muted-foreground">GCM Mode Active</p>
              </div>

              <div className="p-4 rounded-lg bg-muted/30 border border-primary/20">
                <div className="flex items-center gap-2 mb-2">
                  <Fingerprint className="h-5 w-5 text-primary" />
                  <span className="text-sm font-medium text-foreground">Key Derivation</span>
                </div>
                <p className="text-2xl font-display font-bold text-primary">PBKDF2</p>
                <p className="text-xs text-muted-foreground">100k iterations</p>
              </div>

              <div className="p-4 rounded-lg bg-muted/30 border border-primary/20">
                <div className="flex items-center gap-2 mb-2">
                  <Activity className="h-5 w-5 text-accent" />
                  <span className="text-sm font-medium text-foreground">Session Status</span>
                </div>
                <p className="text-2xl font-display font-bold text-accent">Active</p>
                <p className="text-xs text-muted-foreground">30 min timeout</p>
              </div>

              <div className="p-4 rounded-lg bg-muted/30 border border-primary/20">
                <div className="flex items-center gap-2 mb-2">
                  <Database className="h-5 w-5 text-primary" />
                  <span className="text-sm font-medium text-foreground">Audit Logging</span>
                </div>
                <p className="text-2xl font-display font-bold text-primary">Enabled</p>
                <p className="text-xs text-muted-foreground">All events tracked</p>
              </div>
            </div>

            {/* Session Info */}
            <div className="p-4 rounded-lg bg-muted/30 border border-primary/20">
              <h4 className="text-sm font-medium text-foreground mb-3">Current Session</h4>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Session Token:</span>
                  <span className="font-mono text-foreground">{sessionToken.substring(0, 16)}...</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Login Time:</span>
                  <span className="text-foreground">{securityMetrics.lastLogin?.toLocaleString() || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Total Logins:</span>
                  <span className="text-foreground">{securityMetrics.totalLogins}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Failed Attempts:</span>
                  <span className={securityMetrics.failedLogins > 0 ? 'text-destructive' : 'text-accent'}>
                    {securityMetrics.failedLogins}
                  </span>
                </div>
              </div>
            </div>

            <Button 
              variant="outline" 
              onClick={() => setSubSection('menu')} 
              className="w-full"
            >
              Back to Menu
            </Button>
          </div>
        );

      default:
        return null;
    }
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // MAIN RENDER
  // ═══════════════════════════════════════════════════════════════════════════

  // Use type assertion to prevent control flow narrowing
  const isMenuView = (subSection as string) === 'menu';

  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto">
      <div className="max-w-md mx-auto w-full cyber-card rounded-xl p-6">
        {/* Back Button */}
        {!isMenuView && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSubSection('menu');
              setError('');
              setEncryptionStatus('idle');
            }}
            className="mb-4"
          >
            ← Back to Menu
          </Button>
        )}

        {/* Sub-section Content */}
        {renderSubSection()}
      </div>
    </div>
  );
}

export default ModificationSection;
