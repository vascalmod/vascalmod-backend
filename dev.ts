import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });

import express from 'express';
import type { Express, Request, Response } from 'express';
import { createClient } from '@supabase/supabase-js';
import { generateToken, verifyJWT } from './lib/auth';

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';

const app: Express = express();
const PORT = 3001;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
app.use(express.json());

function normalizeHWID(hwid: string): string {
  return hwid.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
}

async function getLocationData(ip: string): Promise<any> {
  try {
    if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost' || ip.startsWith('192.168.')) {
      return { ip, city: 'Localhost', country: 'Local', isp: 'Development', latitude: 0, longitude: 0 };
    }
    
    const response = await fetch(`https://ipapi.co/${ip}/json/`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Express Node.js Backend)', 'Accept': 'application/json' }
    });

    if (!response.ok) throw new Error(`Geolocation API error: ${response.status}`);
    const data = (await response.json()) as Record<string, unknown>;

    if (data.error) throw new Error(data.reason as string);

    return {
      ip,
      city: (data.city as string) || 'Unknown',
      country: (data.country_name as string) || 'Unknown',
      isp: (data.org as string) || 'Unknown',
      latitude: (data.latitude as number) || 0,
      longitude: (data.longitude as number) || 0,
    };
  } catch (error) {
    return { ip, city: 'Unknown', country: 'Unknown', isp: 'Unknown', latitude: 0, longitude: 0 };
  }
}

app.use((req: Request, res: Response, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

app.post('/api/admin-login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error || !data.user) return res.status(401).json({ error: 'Invalid credentials' });

    const { data: adminData } = await supabase.from('admins').select('id').eq('user_id', data.user.id);
    if (!adminData || adminData.length === 0) return res.status(403).json({ error: 'User is not an admin' });

    const token = generateToken({ user_id: data.user.id, email: data.user.email, is_admin: true });
    res.json({ token, user: { id: data.user.id, email: data.user.email } });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// LOGIN (Activation logic mapped to per-device duration)
app.post('/api/login', async (req: Request, res: Response) => {
  try {
    const { license_key, hwid } = req.body;
    if (!license_key || !hwid) return res.status(400).json({ error: 'License key and HWID required' });

    const { data: license, error: licenseError } = await supabase
      .from('licenses')
      .select('*')
      .eq('key', license_key)
      .single();

    if (licenseError || !license) return res.status(404).json({ error: 'Invalid license key' });
    if (license.revoked) return res.status(403).json({ error: 'License has been revoked' });

    let clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
    if (clientIp === '::1' || clientIp === '::ffff:127.0.0.1') clientIp = '127.0.0.1';

    const locationData = await getLocationData(clientIp);
    const normalizedHWID = normalizeHWID(hwid);

    // Auto delete expired devices
    await supabase.from('devices').delete().eq('license_key', license_key).lt('expires_at', new Date().toISOString());

    // Check active devices
    const { data: devices } = await supabase.from('devices').select('*').eq('license_key', license_key);
    const activatedDevices = devices || [];
    const currentDevice = activatedDevices.find((d) => d.hwid === normalizedHWID);

    let status = 'failed';
    let message = 'Login failed';
    let expires_at: string | undefined;

    if (currentDevice) {
      status = 'success';
      message = 'Login successful';
      expires_at = currentDevice.expires_at;
      await supabase.from('devices').update({ last_seen: new Date().toISOString(), ip: clientIp }).eq('id', currentDevice.id);
    } else if (activatedDevices.length >= license.max_devices) {
      status = 'failed_limit';
      message = 'Maximum devices exceeded';
    } else {
      const deviceExpiration = new Date();
      deviceExpiration.setDate(deviceExpiration.getDate() + license.duration_days);
      expires_at = deviceExpiration.toISOString();

      await supabase.from('devices').insert({
        license_key,
        hwid: normalizedHWID,
        ip: clientIp,
        activated_at: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        expires_at: expires_at
      });
      status = 'success';
      message = 'Device activated successfully';
    }

    await supabase.from('login_logs').insert({
      license_key, hwid: normalizedHWID, ip: clientIp, city: locationData.city,
      country: locationData.country, isp: locationData.isp, latitude: locationData.latitude,
      longitude: locationData.longitude, status, timestamp: new Date().toISOString(),
    });

    if (status !== 'success' || !expires_at) return res.status(403).json({ error: message });

    const token = generateToken({ license_key, hwid, is_admin: false }, '7d');
    res.json({ success: true, message, token, expires_at, plan: license.plan, max_devices: license.max_devices });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get Licenses
app.get('/api/licenses', async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token || !verifyJWT(token, true)) return res.status(401).json({ error: 'Unauthorized' });

    const { data: licenses } = await supabase.from('licenses').select('*').order('created_at', { ascending: false });
    
    const licensesWithDeviceCounts = await Promise.all(
      (licenses || []).map(async (license) => {
        const { data: devices } = await supabase.from('devices').select('id').eq('license_key', license.key);
        return { ...license, device_count: devices?.length || 0 };
      })
    );
    res.json({ success: true, data: licensesWithDeviceCounts });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create/Revoke Licenses
app.post('/api/licenses', async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token || !verifyJWT(token, true)) return res.status(401).json({ error: 'Unauthorized' });

    if (req.query.action === 'revoke') {
      const { license_key } = req.body;
      const { data } = await supabase.from('licenses').update({ revoked: true, revoked_at: new Date().toISOString() }).eq('key', license_key).select();
      await supabase.from('devices').delete().eq('license_key', license_key);
      return res.json({ success: true, data });
    }

    const { plan = '1D', max_devices = 3, expiration_days = null, strict_mode = false } = req.body;
    const licenseKey = `LIC-${Date.now()}-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;

    let daysToAdd = 1;
    let displayPlan = plan;

    if (plan === 'custom' && expiration_days) {
      daysToAdd = parseInt(expiration_days);
      displayPlan = `Custom ${daysToAdd}D`;
    } else {
      const planDays: Record<string, number> = { '1D': 1, '3D': 3, '7D': 7, '30D': 30 };
      daysToAdd = planDays[plan] || 1;
    }

    const { data } = await supabase.from('licenses').insert({
      key: licenseKey, plan: displayPlan, max_devices, strict_mode,
      duration_days: daysToAdd, revoked: false, created_at: new Date().toISOString()
    }).select();

    res.status(201).json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/logs', async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token || !verifyJWT(token, true)) return res.status(401).json({ error: 'Unauthorized' });

    const { data } = await supabase.from('login_logs').select('*').order('timestamp', { ascending: false }).limit(50);
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/stats', async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token || !verifyJWT(token, true)) return res.status(401).json({ error: 'Unauthorized' });

    const { data: licenses } = await supabase.from('licenses').select('revoked');
    const { data: devices } = await supabase.from('devices').select('*');
    const { data: logs } = await supabase.from('login_logs').select('*');

    const stats = {
      total_licenses: licenses?.length || 0,
      active_licenses: licenses?.filter((l) => !l.revoked).length || 0,
      total_devices: devices?.length || 0,
      total_logins: logs?.length || 0,
      success_logins: logs?.filter((l: any) => l.status === 'success').length || 0,
    };

    res.json({ success: true, data: stats });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => console.log(`🚀 Dev Server running on http://localhost:${PORT}`));
