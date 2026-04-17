import { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { setCorsHeaders, handleCorsPreFlight } from '../lib/cors';

interface LoginRequest {
  license_key: string;
  hwid: string;
}

interface LoginResponse {
  success: boolean;
  message: string;
  token?: string;
  expires_at?: string;
  error?: string;
}

interface LocationData {
  ip: string;
  city: string;
  country: string;
  isp: string;
  latitude: number;
  longitude: number;
}

// Initialize Supabase
const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_KEY || ''
);

// Normalize HWID (remove special chars, lowercase)
function normalizeHWID(hwid: string): string {
  return hwid.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
}

// Get geolocation data (Hybrid: Vercel headers for Prod, Mock data for Local Dev)
async function getLocationData(req: VercelRequest): Promise<LocationData> {
  const clientIP =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() ||
    (req.headers['x-real-ip'] as string) ||
    req.socket.remoteAddress ||
    'unknown';

  const isLocal =
    process.env.NODE_ENV === 'development' ||
    clientIP === '::1' ||
    clientIP === '127.0.0.1' ||
    clientIP.startsWith('192.168.');

  if (isLocal) {
    return {
      ip: '127.0.0.1',
      city: 'Local Dev City',
      country: 'Local Dev Country',
      isp: 'Localhost ISP',
      latitude: 0,
      longitude: 0,
    };
  }

  // Production on Vercel
  return {
    ip: clientIP,
    city: decodeURIComponent((req.headers['x-vercel-ip-city'] as string) || 'Unknown'),
    country: (req.headers['x-vercel-ip-country'] as string) || 'Unknown',
    isp: 'Unknown', // Vercel does not provide ISP headers natively
    latitude: parseFloat((req.headers['x-vercel-ip-latitude'] as string) || '0'),
    longitude: parseFloat((req.headers['x-vercel-ip-longitude'] as string) || '0'),
  };
}

// Main handler
export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<VercelResponse> {
  // Handle CORS preflight
  if (handleCorsPreFlight(req, res)) {
    return res;
  }

  // Add CORS headers to all responses
  setCorsHeaders(res);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { license_key, hwid } = req.body as LoginRequest;

    if (!license_key || !hwid) {
      return res.status(400).json({
        success: false,
        error: 'license_key and hwid required',
      });
    }

    const normalizedHWID = normalizeHWID(hwid);

    // Get location data instantly via headers or mock
    const locationData = await getLocationData(req);

    // Check license in database
    const { data: license, error: licenseError } = await supabase
      .from('licenses')
      .select('*')
      .eq('key', license_key)
      .single();

    let status = 'failed';
    let success = false;
    let message = 'Login failed';
    let token: string | undefined;
    let expires_at: string | undefined;

    if (!license) {
      message = 'Invalid license key';
    } else if (new Date(license.expires_at) < new Date()) {
      message = 'License expired';
    } else {
      // Check device activation rules
      const { data: devices, error: devicesError } = await supabase
        .from('devices')
        .select('hwid')
        .eq('license_key', license_key);

      const activatedDevices = devices || [];
      const deviceCount = activatedDevices.length;

      // Check if device already registered
      if (activatedDevices.some((d) => d.hwid === normalizedHWID)) {
        // Device already registered - allow login
        success = true;
        status = 'success';
        message = 'Login successful';
      }
      // Check max devices BEFORE inserting new device (applies to all plans)
      else if (deviceCount >= license.max_devices) {
        message = 'Max device limit reached';
      }
      // Device count is under limit - register new device
      else {
        // Register new device
        const { error: insertError } = await supabase.from('devices').insert({
          license_key,
          hwid: normalizedHWID,
          ip: locationData.ip,
          activated_at: new Date().toISOString(),
          last_seen: new Date().toISOString(),
        });

        if (insertError) {
          console.error('Device registration failed:', insertError);
          message = 'Failed to register device';
        } else {
          success = true;
          status = 'success';
          message = 'Login successful';
        }
      }

      if (success) {
        expires_at = license.expires_at;

        // Generate JWT token
        token = jwt.sign(
          {
            license_key,
            hwid: normalizedHWID,
            exp: Math.floor(new Date(license.expires_at).getTime() / 1000),
          },
          process.env.JWT_SECRET || '3ed92d36086fdf3a888cfc54812a83075fc9596b470d2df98a7f45c3d75b5b9d'
        );
      }
    }

    // Log the request
    await supabase.from('login_logs').insert({
      license_key,
      hwid: normalizedHWID,
      ip: locationData.ip,
      city: locationData.city,
      country: locationData.country,
      isp: locationData.isp,
      latitude: locationData.latitude,
      longitude: locationData.longitude,
      status,
      user_agent: req.headers['user-agent'] || null,
      timestamp: new Date().toISOString(),
    });

    if (success) {
      return res.status(200).json({
        success: true,
        message,
        token,
        expires_at,
      });
    } else {
      return res.status(401).json({
        success: false,
        error: message,
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      debug: process.env.NODE_ENV === 'development' ? {
        errorMessage,
        errorType: error instanceof Error ? error.name : typeof error,
        stack: error instanceof Error ? error.stack : undefined,
      } : undefined,
    });
  }   
}