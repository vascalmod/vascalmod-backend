import dotenv from 'dotenv';
const envResult = dotenv.config({ path: '.env.local' });

import express from 'express';
import type { Express, Request, Response } from 'express';
import { createClient } from '@supabase/supabase-js';
import { generateToken, verifyJWT } from './lib/auth';

// Get constants after dotenv loads
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';

const app: Express = express();
const PORT = 3001;

// Initialize Supabase
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// Middleware
app.use(express.json());

// Normalize HWID (remove special chars, lowercase)
function normalizeHWID(hwid: string): string {
  return hwid.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
}

// Get geolocation data from ipapi.co
async function getLocationData(ip: string): Promise<any> {
  try {
    // Skip geolocation for localhost and local network IPs
    if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost' || ip.startsWith('192.168.')) {
      return {
        ip,
        city: 'Localhost',
        country: 'Local',
        isp: 'Development',
        latitude: 0,
        longitude: 0,
      };
    }
    
    // Add User-Agent header so ipapi.co doesn't block the request
    const response = await fetch(`https://ipapi.co/${ip}/json/`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Express Node.js Backend)',
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Geolocation API error: ${response.status}`);
    }

    const data = (await response.json()) as Record<string, unknown>;

    // ipapi.co sometimes returns 200 OK but with an error body (e.g., Rate Limited)
    if (data.error) {
      console.warn('⚠️ ipapi.co returned an error:', data.reason);
      throw new Error(data.reason as string);
    }

    return {
      ip,
      city: (data.city as string) || 'Unknown',
      // Store 2-letter ISO code for react-country-flag
      country: (data.country as string) || (data.country_name as string) || 'Unknown',
      isp: (data.org as string) || 'Unknown',
      latitude: (data.latitude as number) || 0,
      longitude: (data.longitude as number) || 0,
    };
  } catch (error) {
    console.error('⚠️ Geolocation fetch failed:', error);
    return {
      ip,
      city: 'Unknown',
      country: 'Unknown',
      isp: 'Unknown',
      latitude: 0,
      longitude: 0,
    };
  }
}

// CORS
app.use((req: Request, res: Response, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

// Health check
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0',
  });
});

// Admin Login
app.post('/api/admin-login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Authenticate with Supabase
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error || !data.user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if user is admin
    const { data: adminData, error: adminError } = await supabase
      .from('admins')
      .select('id')
      .eq('user_id', data.user.id);

    if (adminError) {
      console.error('❌ Admin query error:', adminError);
      return res.status(500).json({ error: 'Database error', details: adminError.message });
    }

    if (!adminData || adminData.length === 0) {
      return res.status(403).json({ error: 'User is not an admin' });
    }

    // Generate JWT token
    const token = generateToken({
      user_id: data.user.id,
      email: data.user.email,
      is_admin: true,
    });

    res.json({
      token,
      user: {
        id: data.user.id,
        email: data.user.email,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// License Login (activation)
app.post('/api/login', async (req: Request, res: Response) => {
  try {
    const { license_key, hwid } = req.body;

    if (!license_key || !hwid) {
      return res.status(400).json({ error: 'License key and HWID required' });
    }

    // Find license
    const { data: license, error: licenseError } = await supabase
      .from('licenses')
      .select('*')
      .eq('key', license_key)
      .single();

    if (licenseError || !license) {
      console.log('❌ License not found:', license_key);
      return res.status(404).json({ error: 'Invalid license key' });
    }

    // Check if revoked
    if (license.revoked) {
      console.log('❌ License revoked:', license_key);
      return res.status(403).json({ error: 'License has been revoked' });
    }

    // Check if expired
    if (new Date(license.expires_at) < new Date()) {
      console.log('❌ License expired:', license_key);
      return res.status(403).json({ error: 'License has expired' });
    }

    // Get client IP
    let clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || 
                   req.socket.remoteAddress || 
                   'unknown';
    
    if (clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
      clientIp = '127.0.0.1';
    }

    const locationData = await getLocationData(clientIp);
    const normalizedHWID = normalizeHWID(hwid);

    // 1. Check if device already exists
    const { data: existingDevice, error: existingError } = await supabase
      .from('devices')
      .select('id')
      .eq('license_key', license_key)
      .eq('hwid', normalizedHWID)
      .maybeSingle();

    if (existingDevice?.id) {
      const { error: updateError } = await supabase
        .from('devices')
        .update({ last_seen: new Date().toISOString(), ip: clientIp })
        .eq('id', existingDevice.id);
    } else {
      // 2. Check device limit
      const { data: existingDevices, error: countError } = await supabase
        .from('devices')
        .select('id')
        .eq('license_key', license_key);

      const currentDeviceCount = existingDevices?.length || 0;

      if (currentDeviceCount >= license.max_devices) {
        await supabase.from('login_logs').insert({
          license_key,
          hwid: normalizedHWID,
          ip: clientIp,
          city: locationData.city,
          country: locationData.country,
          isp: locationData.isp,
          latitude: locationData.latitude,
          longitude: locationData.longitude,
          status: 'failed_limit',
          timestamp: new Date().toISOString(),
        });
        return res.status(403).json({ error: 'Maximum devices exceeded' });
      }

      // 3. Insert new device
      await supabase.from('devices').insert({
        license_key,
        hwid: normalizedHWID,
        ip: clientIp,
        activated_at: new Date().toISOString(),
        last_seen: new Date().toISOString(),
      });
    }

    // Log the login
    await supabase.from('login_logs').insert({
      license_key,
      hwid: normalizedHWID,
      ip: clientIp,
      city: locationData.city,
      country: locationData.country,
      isp: locationData.isp,
      latitude: locationData.latitude,
      longitude: locationData.longitude,
      status: 'success',
      timestamp: new Date().toISOString(),
    });

    const token = generateToken({ license_key, hwid, is_admin: false }, '7d');

    res.json({
      success: true,
      message: 'License activated',
      token,
      expires_at: license.expires_at,
      plan: license.plan,
      max_devices: license.max_devices,
    });
  } catch (error) {
    console.error('❌ /api/login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get Licenses
app.get('/api/licenses', async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];
    const verified = verifyJWT(token || '', true);

    if (!token || !verified) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: licenses, error } = await supabase
      .from('licenses')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    const licensesWithDeviceCounts = await Promise.all(
      (licenses || []).map(async (license) => {
        const { data: devices } = await supabase
          .from('devices')
          .select('id')
          .eq('license_key', license.key);
        
        return {
          ...license,
          device_count: devices?.length || 0,
        };
      })
    );

    res.json({ success: true, data: licensesWithDeviceCounts });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create or Revoke License
app.post('/api/licenses', async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];
    const verified = verifyJWT(token || '', true);

    if (!verified) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const action = req.query.action;

    if (action === 'revoke') {
      const { license_key } = req.body;
      const { data, error } = await supabase
        .from('licenses')
        .update({ revoked: true, revoked_at: new Date().toISOString() })
        .eq('key', license_key)
        .select();

      if (error) throw error;
      return res.json({ success: true, data });
    }

    // Create License (default)
    const { 
      plan = '1D', 
      max_devices = 3, 
      expiration_days = null, 
      strict_mode = false 
    } = req.body;

    const licenseKey = `LIC-${Date.now()}-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;

    const expires_at = new Date();
    let daysToAdd = 1;
    let displayPlan = plan;

    if (plan === 'custom' && expiration_days) {
      daysToAdd = parseInt(expiration_days);
      // 🔥 Save as "Custom 365D" to DB
      displayPlan = `Custom ${daysToAdd}D`; 
    } else {
      const planDays: Record<string, number> = {
        '1D': 1,
        '3D': 3,
        '7D': 7,
        '30D': 30,
      };
      daysToAdd = planDays[plan] || 1;
    }

    expires_at.setDate(expires_at.getDate() + daysToAdd);

    const { data, error } = await supabase
      .from('licenses')
      .insert({
        key: licenseKey,
        plan: displayPlan,
        max_devices,
        expires_at: expires_at.toISOString(),
        strict_mode,
        revoked: false,
      })
      .select();

    if (error) throw error;

    res.status(201).json({
      success: true,
      data,
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get Logs
app.get('/api/logs', async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token || !verifyJWT(token, true)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data, error } = await supabase
      .from('login_logs')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(50);

    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get Stats
app.get('/api/stats', async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token || !verifyJWT(token, true)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data: licenses } = await supabase.from('licenses').select('*');
    const { data: devices } = await supabase.from('devices').select('*');
    const { data: logs } = await supabase.from('login_logs').select('*');

    const stats = {
      total_licenses: licenses?.length || 0,
      active_licenses: licenses?.filter((l: any) => !l.revoked).length || 0,
      total_devices: devices?.length || 0,
      total_logins: logs?.length || 0,
      success_logins: logs?.filter((l: any) => l.status === 'success').length || 0,
    };

    res.json({ success: true, data: stats });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.use((req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found', path: req.path });
});

app.listen(PORT, () => {
  console.log(`🚀 Dev Server running on http://localhost:${PORT}`);
});
