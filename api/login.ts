import { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import { setCorsHeaders, handleCorsPreFlight } from '../lib/cors';

interface LoginRequest {
  license_key: string;
  hwid: string;
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

// Normalize HWID
function normalizeHWID(hwid: string): string {
  return hwid.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
}

// Get geolocation data
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

  return {
    ip: clientIP,
    city: decodeURIComponent((req.headers['x-vercel-ip-city'] as string) || 'Unknown'),
    country: (req.headers['x-vercel-ip-country'] as string) || 'Unknown',
    isp: 'Unknown', 
    latitude: parseFloat((req.headers['x-vercel-ip-latitude'] as string) || '0'),
    longitude: parseFloat((req.headers['x-vercel-ip-longitude'] as string) || '0'),
  };
}

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<VercelResponse> {
  if (handleCorsPreFlight(req, res)) return res;
  setCorsHeaders(res);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { license_key, hwid } = req.body as LoginRequest;

    if (!license_key || !hwid) {
      return res.status(400).json({ success: false, error: 'license_key and hwid required' });
    }

    const normalizedHWID = normalizeHWID(hwid);
    const locationData = await getLocationData(req);

    // 1. Fetch License
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

    if (!license || licenseError) {
      message = 'Invalid license key';
    } else if (license.revoked) {
      message = 'License has been revoked';
    } else {
      
      // 2. Auto-delete EXPIRED devices for this key to free up slots
      await supabase
        .from('devices')
        .delete()
        .eq('license_key', license_key)
        .lt('expires_at', new Date().toISOString());

      // 3. Fetch current active devices
      const { data: devices } = await supabase
        .from('devices')
        .select('*')
        .eq('license_key', license_key);

      const activatedDevices = devices || [];
      const currentDevice = activatedDevices.find((d) => d.hwid === normalizedHWID);

      // 4. Logic core
      if (currentDevice) {
        // Device is already registered and active
        success = true;
        status = 'success';
        message = 'Login successful';
        expires_at = currentDevice.expires_at;

        // Update last seen
        await supabase.from('devices').update({ 
          last_seen: new Date().toISOString(), 
          ip: locationData.ip 
        }).eq('id', currentDevice.id);

      } else if (activatedDevices.length >= license.max_devices) {
        // Max devices reached, no room for a new HWID
        message = 'Max device limit reached';
        status = 'failed_limit';
      } else {
        // Slot available: Register NEW device and start its personal timer
        const deviceExpiration = new Date();
        deviceExpiration.setDate(deviceExpiration.getDate() + license.duration_days);
        expires_at = deviceExpiration.toISOString();

        const { error: insertError } = await supabase.from('devices').insert({
          license_key,
          hwid: normalizedHWID,
          ip: locationData.ip,
          activated_at: new Date().toISOString(),
          last_seen: new Date().toISOString(),
          expires_at: expires_at
        });

        if (insertError) {
          console.error('Device registration failed:', insertError);
          message = 'Failed to register device';
        } else {
          success = true;
          status = 'success';
          message = 'Device activated successfully';
        }
      }

      // Generate token
      if (success && expires_at) {
        token = jwt.sign(
          {
            license_key,
            hwid: normalizedHWID,
            exp: Math.floor(new Date(expires_at).getTime() / 1000),
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
        plan: license?.plan,
        max_devices: license?.max_devices
      });
    } else {
      return res.status(401).json({ success: false, error: message });
    }
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }   
}
