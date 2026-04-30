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

    // CHANGED: We now fetch the actual devices array to accurately count and verify expiry dates
    const { data: licenses, error } = await supabase
      .from('licenses')
      .select('*, devices(id, hwid, activated_at, expires_at)')
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    // CHANGED: Map over the data to format it cleanly for the frontend dashboard
    const formattedLicenses = licenses.map((license) => {
      const total_slots = license.max_devices;
      const used_slots = license.devices ? license.devices.length : 0;

      return {
        ...license,
        active_devices_text: `${used_slots}/${total_slots}`,
        duration_text: `${license.duration_days} Day(s) / Device`,
        status: license.revoked ? 'Revoked' : 'Active',
        devices: (license.devices || []).map((dev: any) => {
          // Calculate if this specific device has expired
          const isExpired = new Date() > new Date(dev.expires_at);
          
          return {
            ...dev,
            status: isExpired ? 'Expired' : 'Active'
          };
        })
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
    } = req.body;

    // Generate unique license key
    const licenseKey = `VSCL-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;

    // Calculate dynamic plan name and duration
    let daysToAdd = 1;
    let displayPlan = plan;

    if (plan === 'custom' && expiration_days) {
      daysToAdd = parseInt(expiration_days);
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

    // Insert with duration_days instead of expires_at
    const { data, error } = await supabase.from('licenses').insert({
      key: licenseKey,
      plan: displayPlan,
      max_devices,
      strict_mode,
      duration_days: daysToAdd,
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
