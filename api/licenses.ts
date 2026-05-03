import { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import { verifyJWT } from '../lib/auth';
import { setCorsHeaders, handleCorsPreFlight } from '../lib/cors';
import crypto from 'crypto';

const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_KEY || ''
);

// GET /api/licenses - List all licenses (admin only)
async function getLicenses(req: VercelRequest, res: VercelResponse) {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const verified = verifyJWT(token || '', true);

    if (!verified) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // FIXED: Fetch licenses and devices separately to bypass Supabase Foreign Key limitations
    const { data: licenses, error } = await supabase
      .from('licenses')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    const { data: allDevices } = await supabase.from('devices').select('*');

    const formattedLicenses = licenses.map((license) => {
      const total_slots = license.max_devices;
      // Manually filter devices belonging to this license key
      const licenseDevices = allDevices 
        ? allDevices.filter(d => d.license_key === license.key)
        : [];
      
      const used_slots = licenseDevices.length;

      return {
        ...license,
        active_devices_text: `${used_slots}/${total_slots}`,
        duration_text: `${license.duration_days} Day(s) / Device`,
        status: license.revoked ? 'Revoked' : 'Active',
        devices: licenseDevices.map((dev: any) => ({
          ...dev,
          status: new Date() > new Date(dev.expires_at) ? 'Expired' : 'Active'
        }))
      };
    });

    return res.status(200).json({
      success: true,
      data: formattedLicenses,
    });
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
}

// POST /api/licenses/create - Create new license (admin only)
async function createLicense(req: VercelRequest, res: VercelResponse) {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const verified = verifyJWT(token || '', true);

    if (!verified) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const {
      plan = '1D',
      max_devices = 3,
      strict_mode = false,
      expiration_days = null,
      expiration_hours = 0,
      expiration_minutes = 0,
    } = req.body;

    // Generate unique license key
    const licenseKey = `VSCL-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;

    // Calculate total duration in seconds from days + hours + minutes
    let totalSeconds = 0;
    let displayPlan = plan;

    if (plan === 'custom') {
      const d = parseInt(expiration_days) || 0;
      const h = parseInt(expiration_hours) || 0;
      const m = parseInt(expiration_minutes) || 0;
      totalSeconds = (d * 86400) + (h * 3600) + (m * 60);
      displayPlan = `Custom ${d}d ${h}h ${m}m`;
    } else {
      const planDays: Record<string, number> = {
        '1D': 1,
        '3D': 3,
        '7D': 7,
        '30D': 30,
      };
      totalSeconds = (planDays[plan] || 1) * 86400;
    }

    // Insert with duration_seconds for precise expiration control
    const { data, error } = await supabase.from('licenses').insert({
      key: licenseKey,
      plan: displayPlan,
      max_devices,
      strict_mode,
      duration_days: Math.floor(totalSeconds / 86400),
      duration_seconds: totalSeconds,
      created_at: new Date().toISOString(),
    });

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    return res.status(201).json({
      success: true,
      data: {
        license_key: licenseKey,
        plan: displayPlan,
        max_devices,
        strict_mode,
        duration_days: daysToAdd,
      },
    });
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
}

// POST /api/licenses/revoke - Revoke a license (admin only)
async function revokeLicense(req: VercelRequest, res: VercelResponse) {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const verified = verifyJWT(token || '', true);

    if (!verified) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { license_key } = req.body;

    const { error } = await supabase
      .from('licenses')
      .update({ revoked: true, revoked_at: new Date().toISOString() })
      .eq('key', license_key);

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    // Optional: Delete all devices associated with a revoked key instantly
    await supabase.from('devices').delete().eq('license_key', license_key);

    return res.status(200).json({
      success: true,
      message: 'License revoked',
    });
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
}

// Main router
export default function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<VercelResponse> | VercelResponse {
  // Handle CORS preflight
  if (handleCorsPreFlight(req, res)) {
    return res;
  }

  // Add CORS headers to all responses
  setCorsHeaders(res);

  const { query } = req;
  const method = req.method || 'GET';

  // GET /api/licenses
  if (method === 'GET' && !query.action) {
    return getLicenses(req, res);
  }

  // POST /api/licenses/create
  if (method === 'POST' && query.action === 'create') {
    return createLicense(req, res);
  }

  // POST /api/licenses/revoke
  if (method === 'POST' && query.action === 'revoke') {
    return revokeLicense(req, res);
  }

  return res.status(404).json({ error: 'Not found' });
}
