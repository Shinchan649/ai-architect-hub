/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                    VEXX AI - SECURITY AUDIT MODULE                            ║
 * ║                                                                                ║
 * ║  This module provides comprehensive security auditing capabilities            ║
 * ║  including threat detection, anomaly monitoring, and security logging.        ║
 * ║                                                                                ║
 * ║  Features:                                                                    ║
 * ║  - Real-time security event monitoring                                       ║
 * ║  - Anomaly detection algorithms                                              ║
 * ║  - Brute force attack prevention                                             ║
 * ║  - Session management and validation                                         ║
 * ║  - Security incident reporting                                               ║
 * ║                                                                                ║
 * ║  Author: VexX AI Security Team                                               ║
 * ║  Version: 2.0.0                                                               ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

import { generateSecureId, computeSHA256Hash, generateSecureToken } from './encryption';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Security event severity levels
 */
export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Security event types
 */
export type SecurityEventType =
  | 'authentication_success'
  | 'authentication_failure'
  | 'authorization_denied'
  | 'brute_force_attempt'
  | 'session_created'
  | 'session_expired'
  | 'session_invalidated'
  | 'data_access'
  | 'data_modification'
  | 'data_deletion'
  | 'encryption_operation'
  | 'decryption_operation'
  | 'api_access'
  | 'rate_limit_exceeded'
  | 'suspicious_activity'
  | 'integrity_violation'
  | 'configuration_change'
  | 'system_alert';

/**
 * Security event structure
 */
export interface SecurityEvent {
  /** Unique event identifier */
  id: string;
  /** Event type */
  type: SecurityEventType;
  /** Severity level */
  severity: SecuritySeverity;
  /** Event timestamp */
  timestamp: number;
  /** User or session identifier */
  userId?: string;
  /** Session identifier */
  sessionId?: string;
  /** IP address (if available) */
  ipAddress?: string;
  /** User agent string */
  userAgent?: string;
  /** Event description */
  description: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
  /** Whether the event was handled */
  handled: boolean;
  /** Hash for integrity verification */
  hash: string;
}

/**
 * Session information
 */
export interface SecuritySession {
  /** Session identifier */
  id: string;
  /** User identifier */
  userId: string;
  /** Session creation timestamp */
  createdAt: number;
  /** Last activity timestamp */
  lastActivity: number;
  /** Session expiration timestamp */
  expiresAt: number;
  /** Whether the session is valid */
  isValid: boolean;
  /** Session fingerprint for verification */
  fingerprint: string;
  /** Number of authentication attempts */
  authAttempts: number;
  /** Session metadata */
  metadata: Record<string, unknown>;
}

/**
 * Rate limit entry
 */
export interface RateLimitEntry {
  /** Identifier (IP, user ID, etc.) */
  identifier: string;
  /** Number of requests in the window */
  requestCount: number;
  /** Window start timestamp */
  windowStart: number;
  /** Whether currently blocked */
  isBlocked: boolean;
  /** Block expiration timestamp */
  blockExpiresAt?: number;
}

/**
 * Security configuration
 */
export interface SecurityConfig {
  /** Maximum authentication attempts before lockout */
  maxAuthAttempts: number;
  /** Lockout duration in milliseconds */
  lockoutDuration: number;
  /** Session timeout in milliseconds */
  sessionTimeout: number;
  /** Rate limit window in milliseconds */
  rateLimitWindow: number;
  /** Maximum requests per rate limit window */
  maxRequestsPerWindow: number;
  /** Enable anomaly detection */
  enableAnomalyDetection: boolean;
  /** Maximum events to store in memory */
  maxEventsInMemory: number;
  /** Event retention period in milliseconds */
  eventRetentionPeriod: number;
}

/**
 * Security statistics
 */
export interface SecurityStatistics {
  /** Total events logged */
  totalEvents: number;
  /** Events by severity */
  eventsBySeverity: Record<SecuritySeverity, number>;
  /** Events by type */
  eventsByType: Record<string, number>;
  /** Active sessions count */
  activeSessions: number;
  /** Blocked identifiers count */
  blockedIdentifiers: number;
  /** Last security scan timestamp */
  lastScanTimestamp: number;
  /** Security score (0-100) */
  securityScore: number;
}

/**
 * Threat assessment result
 */
export interface ThreatAssessment {
  /** Threat level (0-100) */
  threatLevel: number;
  /** Identified threats */
  threats: Array<{
    type: string;
    severity: SecuritySeverity;
    description: string;
    mitigations: string[];
  }>;
  /** Recommended actions */
  recommendations: string[];
  /** Assessment timestamp */
  timestamp: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_SECURITY_CONFIG: SecurityConfig = {
  maxAuthAttempts: 5,
  lockoutDuration: 15 * 60 * 1000, // 15 minutes
  sessionTimeout: 30 * 60 * 1000, // 30 minutes
  rateLimitWindow: 60 * 1000, // 1 minute
  maxRequestsPerWindow: 100,
  enableAnomalyDetection: true,
  maxEventsInMemory: 10000,
  eventRetentionPeriod: 7 * 24 * 60 * 60 * 1000, // 7 days
};

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY AUDIT CLASS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * SecurityAudit provides comprehensive security monitoring and auditing
 */
export class SecurityAudit {
  private static instance: SecurityAudit | null = null;
  
  private config: SecurityConfig;
  private events: SecurityEvent[] = [];
  private sessions: Map<string, SecuritySession> = new Map();
  private rateLimits: Map<string, RateLimitEntry> = new Map();
  private authAttempts: Map<string, number[]> = new Map();
  
  /**
   * Private constructor for singleton pattern
   */
  private constructor(config?: Partial<SecurityConfig>) {
    this.config = { ...DEFAULT_SECURITY_CONFIG, ...config };
    this.initialize();
  }
  
  /**
   * Gets the singleton instance of SecurityAudit
   */
  public static getInstance(config?: Partial<SecurityConfig>): SecurityAudit {
    if (!SecurityAudit.instance) {
      SecurityAudit.instance = new SecurityAudit(config);
    }
    return SecurityAudit.instance;
  }
  
  /**
   * Initializes the security audit system
   */
  private initialize(): void {
    // Load persisted events
    this.loadPersistedEvents();
    
    // Start cleanup interval
    setInterval(() => {
      this.cleanupExpiredData();
    }, 60000); // Run every minute
    
    // Log initialization
    this.logEvent({
      type: 'system_alert',
      severity: 'low',
      description: 'Security audit system initialized',
    });
  }
  
  /**
   * Loads persisted events from storage
   */
  private loadPersistedEvents(): void {
    try {
      const storedEvents = localStorage.getItem('vexai_security_events');
      if (storedEvents) {
        this.events = JSON.parse(storedEvents);
      }
      
      const storedSessions = localStorage.getItem('vexai_security_sessions');
      if (storedSessions) {
        const sessionsArray: SecuritySession[] = JSON.parse(storedSessions);
        sessionsArray.forEach(session => {
          this.sessions.set(session.id, session);
        });
      }
    } catch (error) {
      console.error('Failed to load persisted security data:', error);
    }
  }
  
  /**
   * Persists events to storage
   */
  private persistEvents(): void {
    try {
      // Keep only recent events
      const cutoff = Date.now() - this.config.eventRetentionPeriod;
      const recentEvents = this.events.filter(e => e.timestamp > cutoff);
      
      localStorage.setItem('vexai_security_events', JSON.stringify(recentEvents.slice(0, this.config.maxEventsInMemory)));
      localStorage.setItem('vexai_security_sessions', JSON.stringify(Array.from(this.sessions.values())));
    } catch (error) {
      console.error('Failed to persist security data:', error);
    }
  }
  
  /**
   * Cleans up expired data
   */
  private cleanupExpiredData(): void {
    const now = Date.now();
    
    // Clean expired events
    const cutoff = now - this.config.eventRetentionPeriod;
    this.events = this.events.filter(e => e.timestamp > cutoff);
    
    // Clean expired sessions
    for (const [sessionId, session] of this.sessions) {
      if (session.expiresAt < now) {
        this.sessions.delete(sessionId);
        this.logEvent({
          type: 'session_expired',
          severity: 'low',
          description: `Session ${sessionId} expired`,
          sessionId,
        });
      }
    }
    
    // Clean expired rate limits
    for (const [identifier, entry] of this.rateLimits) {
      if (entry.blockExpiresAt && entry.blockExpiresAt < now) {
        this.rateLimits.delete(identifier);
      }
    }
    
    this.persistEvents();
  }
  
  /**
   * Logs a security event
   */
  public async logEvent(event: Omit<SecurityEvent, 'id' | 'timestamp' | 'handled' | 'hash'>): Promise<SecurityEvent> {
    const fullEvent: SecurityEvent = {
      ...event,
      id: generateSecureId(16),
      timestamp: Date.now(),
      handled: false,
      hash: '',
    };
    
    // Compute event hash for integrity
    const eventString = JSON.stringify({ ...fullEvent, hash: '' });
    fullEvent.hash = await computeSHA256Hash(eventString);
    
    this.events.unshift(fullEvent);
    
    // Limit events in memory
    if (this.events.length > this.config.maxEventsInMemory) {
      this.events = this.events.slice(0, this.config.maxEventsInMemory);
    }
    
    // Persist events
    this.persistEvents();
    
    // Check for anomalies if enabled
    if (this.config.enableAnomalyDetection) {
      this.detectAnomalies(fullEvent);
    }
    
    return fullEvent;
  }
  
  /**
   * Detects anomalies in security events
   */
  private detectAnomalies(event: SecurityEvent): void {
    // Check for repeated authentication failures
    if (event.type === 'authentication_failure' && event.userId) {
      const recentFailures = this.events.filter(
        e => e.type === 'authentication_failure' &&
        e.userId === event.userId &&
        e.timestamp > Date.now() - this.config.rateLimitWindow
      );
      
      if (recentFailures.length >= this.config.maxAuthAttempts) {
        this.logEvent({
          type: 'brute_force_attempt',
          severity: 'high',
          description: `Multiple authentication failures detected for user ${event.userId}`,
          userId: event.userId,
          metadata: { failureCount: recentFailures.length },
        });
      }
    }
    
    // Check for unusual activity patterns
    const recentEvents = this.events.filter(
      e => e.timestamp > Date.now() - 60000 // Last minute
    );
    
    if (recentEvents.length > 100) {
      this.logEvent({
        type: 'suspicious_activity',
        severity: 'medium',
        description: 'Unusually high activity detected',
        metadata: { eventCount: recentEvents.length },
      });
    }
  }
  
  /**
   * Records an authentication attempt
   */
  public async recordAuthAttempt(
    identifier: string,
    success: boolean,
    metadata?: Record<string, unknown>
  ): Promise<{ allowed: boolean; remainingAttempts: number; lockoutExpires?: number }> {
    const now = Date.now();
    
    // Get or create attempt history
    let attempts = this.authAttempts.get(identifier) || [];
    
    // Clean old attempts
    attempts = attempts.filter(t => t > now - this.config.lockoutDuration);
    
    if (!success) {
      attempts.push(now);
      this.authAttempts.set(identifier, attempts);
      
      await this.logEvent({
        type: 'authentication_failure',
        severity: 'medium',
        description: `Authentication failed for ${identifier}`,
        userId: identifier,
        metadata,
      });
      
      // Check if locked out
      if (attempts.length >= this.config.maxAuthAttempts) {
        const lockoutExpires = now + this.config.lockoutDuration;
        
        await this.logEvent({
          type: 'brute_force_attempt',
          severity: 'high',
          description: `Account ${identifier} locked due to multiple failed attempts`,
          userId: identifier,
          metadata: { lockoutExpires },
        });
        
        return {
          allowed: false,
          remainingAttempts: 0,
          lockoutExpires,
        };
      }
    } else {
      // Clear attempts on success
      this.authAttempts.delete(identifier);
      
      await this.logEvent({
        type: 'authentication_success',
        severity: 'low',
        description: `Authentication successful for ${identifier}`,
        userId: identifier,
        metadata,
      });
    }
    
    return {
      allowed: true,
      remainingAttempts: Math.max(0, this.config.maxAuthAttempts - attempts.length),
    };
  }
  
  /**
   * Creates a new security session
   */
  public async createSession(
    userId: string,
    metadata?: Record<string, unknown>
  ): Promise<SecuritySession> {
    const now = Date.now();
    const sessionId = generateSecureToken(32);
    
    // Generate session fingerprint
    const fingerprintData = `${userId}:${now}:${navigator.userAgent || 'unknown'}`;
    const fingerprint = await computeSHA256Hash(fingerprintData);
    
    const session: SecuritySession = {
      id: sessionId,
      userId,
      createdAt: now,
      lastActivity: now,
      expiresAt: now + this.config.sessionTimeout,
      isValid: true,
      fingerprint: fingerprint.slice(0, 16),
      authAttempts: 0,
      metadata: metadata || {},
    };
    
    this.sessions.set(sessionId, session);
    
    await this.logEvent({
      type: 'session_created',
      severity: 'low',
      description: `Session created for user ${userId}`,
      userId,
      sessionId,
    });
    
    this.persistEvents();
    
    return session;
  }
  
  /**
   * Validates a session
   */
  public validateSession(sessionId: string): { valid: boolean; session?: SecuritySession; error?: string } {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      return { valid: false, error: 'Session not found' };
    }
    
    const now = Date.now();
    
    if (!session.isValid) {
      return { valid: false, error: 'Session has been invalidated' };
    }
    
    if (session.expiresAt < now) {
      session.isValid = false;
      return { valid: false, error: 'Session has expired' };
    }
    
    // Update last activity
    session.lastActivity = now;
    session.expiresAt = now + this.config.sessionTimeout;
    
    return { valid: true, session };
  }
  
  /**
   * Invalidates a session
   */
  public async invalidateSession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      return false;
    }
    
    session.isValid = false;
    
    await this.logEvent({
      type: 'session_invalidated',
      severity: 'low',
      description: `Session ${sessionId} invalidated`,
      sessionId,
      userId: session.userId,
    });
    
    return true;
  }
  
  /**
   * Checks rate limit for an identifier
   */
  public checkRateLimit(identifier: string): { allowed: boolean; remaining: number; resetAt: number } {
    const now = Date.now();
    let entry = this.rateLimits.get(identifier);
    
    // Clean old window
    if (entry && entry.windowStart + this.config.rateLimitWindow < now) {
      entry = undefined;
    }
    
    if (!entry) {
      entry = {
        identifier,
        requestCount: 0,
        windowStart: now,
        isBlocked: false,
      };
    }
    
    // Check if blocked
    if (entry.isBlocked && entry.blockExpiresAt && entry.blockExpiresAt > now) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: entry.blockExpiresAt,
      };
    }
    
    entry.requestCount++;
    
    if (entry.requestCount > this.config.maxRequestsPerWindow) {
      entry.isBlocked = true;
      entry.blockExpiresAt = now + this.config.lockoutDuration;
      
      this.logEvent({
        type: 'rate_limit_exceeded',
        severity: 'medium',
        description: `Rate limit exceeded for ${identifier}`,
        metadata: { requestCount: entry.requestCount },
      });
      
      this.rateLimits.set(identifier, entry);
      
      return {
        allowed: false,
        remaining: 0,
        resetAt: entry.blockExpiresAt,
      };
    }
    
    this.rateLimits.set(identifier, entry);
    
    return {
      allowed: true,
      remaining: this.config.maxRequestsPerWindow - entry.requestCount,
      resetAt: entry.windowStart + this.config.rateLimitWindow,
    };
  }
  
  /**
   * Gets security events with optional filtering
   */
  public getEvents(options?: {
    type?: SecurityEventType;
    severity?: SecuritySeverity;
    userId?: string;
    sessionId?: string;
    since?: number;
    limit?: number;
  }): SecurityEvent[] {
    let filtered = [...this.events];
    
    if (options?.type) {
      filtered = filtered.filter(e => e.type === options.type);
    }
    
    if (options?.severity) {
      filtered = filtered.filter(e => e.severity === options.severity);
    }
    
    if (options?.userId) {
      filtered = filtered.filter(e => e.userId === options.userId);
    }
    
    if (options?.sessionId) {
      filtered = filtered.filter(e => e.sessionId === options.sessionId);
    }
    
    if (options?.since) {
      filtered = filtered.filter(e => e.timestamp > options.since);
    }
    
    if (options?.limit) {
      filtered = filtered.slice(0, options.limit);
    }
    
    return filtered;
  }
  
  /**
   * Gets security statistics
   */
  public getStatistics(): SecurityStatistics {
    const eventsBySeverity: Record<SecuritySeverity, number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };
    
    const eventsByType: Record<string, number> = {};
    
    for (const event of this.events) {
      eventsBySeverity[event.severity]++;
      eventsByType[event.type] = (eventsByType[event.type] || 0) + 1;
    }
    
    const activeSessions = Array.from(this.sessions.values()).filter(s => s.isValid).length;
    const blockedIdentifiers = Array.from(this.rateLimits.values()).filter(r => r.isBlocked).length;
    
    // Calculate security score
    const criticalWeight = eventsBySeverity.critical * 25;
    const highWeight = eventsBySeverity.high * 10;
    const mediumWeight = eventsBySeverity.medium * 5;
    const lowWeight = eventsBySeverity.low * 1;
    
    const totalWeight = criticalWeight + highWeight + mediumWeight + lowWeight;
    const securityScore = Math.max(0, Math.min(100, 100 - totalWeight / 10));
    
    return {
      totalEvents: this.events.length,
      eventsBySeverity,
      eventsByType,
      activeSessions,
      blockedIdentifiers,
      lastScanTimestamp: Date.now(),
      securityScore,
    };
  }
  
  /**
   * Performs a threat assessment
   */
  public async performThreatAssessment(): Promise<ThreatAssessment> {
    const threats: ThreatAssessment['threats'] = [];
    const recommendations: string[] = [];
    let threatLevel = 0;
    
    // Check for recent critical events
    const recentCritical = this.events.filter(
      e => e.severity === 'critical' && e.timestamp > Date.now() - 3600000
    );
    
    if (recentCritical.length > 0) {
      threatLevel += 40;
      threats.push({
        type: 'Critical Security Events',
        severity: 'critical',
        description: `${recentCritical.length} critical security events in the last hour`,
        mitigations: ['Review critical events immediately', 'Consider system lockdown'],
      });
    }
    
    // Check for brute force attempts
    const bruteForceAttempts = this.events.filter(
      e => e.type === 'brute_force_attempt' && e.timestamp > Date.now() - 86400000
    );
    
    if (bruteForceAttempts.length > 0) {
      threatLevel += 25;
      threats.push({
        type: 'Brute Force Attacks',
        severity: 'high',
        description: `${bruteForceAttempts.length} brute force attempts in the last 24 hours`,
        mitigations: ['Strengthen password policies', 'Enable two-factor authentication', 'Review access logs'],
      });
    }
    
    // Check for rate limit violations
    const rateLimitViolations = this.events.filter(
      e => e.type === 'rate_limit_exceeded' && e.timestamp > Date.now() - 3600000
    );
    
    if (rateLimitViolations.length > 5) {
      threatLevel += 15;
      threats.push({
        type: 'Rate Limit Violations',
        severity: 'medium',
        description: `${rateLimitViolations.length} rate limit violations in the last hour`,
        mitigations: ['Review rate limiting configuration', 'Investigate source of requests'],
      });
    }
    
    // General recommendations
    if (threatLevel < 20) {
      recommendations.push('Security posture is good. Continue monitoring.');
    } else if (threatLevel < 50) {
      recommendations.push('Elevated threat level detected. Review recent security events.');
      recommendations.push('Consider enabling additional security measures.');
    } else {
      recommendations.push('High threat level detected. Immediate action required.');
      recommendations.push('Review all critical and high severity events.');
      recommendations.push('Consider temporary system lockdown.');
    }
    
    await this.logEvent({
      type: 'system_alert',
      severity: threatLevel > 50 ? 'high' : threatLevel > 20 ? 'medium' : 'low',
      description: 'Threat assessment completed',
      metadata: { threatLevel, threatCount: threats.length },
    });
    
    return {
      threatLevel: Math.min(100, threatLevel),
      threats,
      recommendations,
      timestamp: Date.now(),
    };
  }
  
  /**
   * Clears all security data
   */
  public clearAll(): void {
    this.events = [];
    this.sessions.clear();
    this.rateLimits.clear();
    this.authAttempts.clear();
    
    localStorage.removeItem('vexai_security_events');
    localStorage.removeItem('vexai_security_sessions');
  }
  
  /**
   * Exports security report
   */
  public async exportSecurityReport(): Promise<string> {
    const statistics = this.getStatistics();
    const assessment = await this.performThreatAssessment();
    
    const report = {
      generatedAt: new Date().toISOString(),
      statistics,
      assessment,
      recentEvents: this.events.slice(0, 100),
      activeSessions: Array.from(this.sessions.values()).filter(s => s.isValid),
      config: this.config,
    };
    
    return JSON.stringify(report, null, 2);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SINGLETON INSTANCE EXPORT
// ═══════════════════════════════════════════════════════════════════════════════

export const securityAudit = SecurityAudit.getInstance();

export default securityAudit;
