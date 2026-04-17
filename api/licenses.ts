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

    const { data: licenses, error } = await supabase
      .from('licenses')
      .select('*, devices(count)');

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    return res.status(200).json({
      success: true,
      data: licenses,
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
      plan = 'standard',
      max_devices = 3,
      strict_mode = false,
    } = req.body;

    // Generate unique license key
    const licenseKey = `LIC-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;

    // Calculate expiration based on plan
    const expiresAt = new Date();
    const planDays: Record<string, number> = {
      starter: 1,
      standard: 3,
      premium: 7,
      enterprise: 30,
    };

    expiresAt.setDate(expiresAt.getDate() + (planDays[plan] || 3));

    const { data, error } = await supabase.from('licenses').insert({
      key: licenseKey,
      plan,
      max_devices,
      strict_mode,
      expires_at: expiresAt.toISOString(),
      created_at: new Date().toISOString(),
    });

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    return res.status(201).json({
      success: true,
      data: {
        license_key: licenseKey,
        plan,
        max_devices,
        strict_mode,
        expires_at: expiresAt.toISOString(),
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
