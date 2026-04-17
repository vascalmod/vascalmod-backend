/**
 * Utility functions for the License Management System
 */

/**
 * Normalize hardware ID (HWID)
 * Removes special characters and converts to lowercase
 */
export function normalizeHWID(hwid: string): string {
  if (!hwid) return '';
  return hwid.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
}

/**
 * Validate license key format
 */
export function isValidLicenseKey(key: string): boolean {
  return /^LIC-[A-F0-9]{32}$/.test(key);
}

/**
 * Get plan duration in days
 */
export function getPlanDays(plan: string): number {
  const planDays: Record<string, number> = {
    starter: 1,
    standard: 3,
    premium: 7,
    enterprise: 30,
  };
  return planDays[plan] || 3;
}

/**
 * Calculate license expiration date
 */
export function calculateExpiration(plan: string): Date {
  const days = getPlanDays(plan);
  const date = new Date();
  date.setDate(date.getDate() + days);
  return date;
}

/**
 * Check if license is expired
 */
export function isLicenseExpired(expiresAt: string | Date): boolean {
  return new Date(expiresAt) < new Date();
}

/**
 * Get client IP from request
 */
export function getClientIP(req: any): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return (forwarded as string).split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

/**
 * Format location data for display
 */
export function formatLocation(location: any): string {
  if (!location) return 'Unknown';
  const { city, country } = location;
  if (city && country) {
    return `${city}, ${country}`;
  }
  return country || 'Unknown';
}
