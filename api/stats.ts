import { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import { setCorsHeaders, handleCorsPreFlight } from '../lib/cors';
import { verifyJWT } from '../lib/auth';

const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || ''
);

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (handleCorsPreFlight(req, res)) return res;
  setCorsHeaders(res);

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const verified = verifyJWT(token || '', true);
    if (!verified) return res.status(401).json({ error: 'Unauthorized' });

    // 1. Total Licenses
    const { count: totalLicenses } = await supabase
      .from('licenses')
      .select('*', { count: 'exact', head: true });

    // 2. Active Devices (Devices where expires_at is in the future)
    const now = new Date().toISOString();
    const { count: activeDevices } = await supabase
      .from('devices')
      .select('*', { count: 'exact', head: true })
      .gt('expires_at', now);

    // 3. Total Devices
    const { count: totalDevices } = await supabase
      .from('devices')
      .select('*', { count: 'exact', head: true });

    // 4. Today's Logs (from the login_logs table)
    const startOfToday = new Date();
    startOfToday.setUTCHours(0, 0, 0, 0); // Sets time to midnight UTC securely
    const { count: todaysLogs } = await supabase
      .from('login_logs')
      .select('*', { count: 'exact', head: true })
      .gte('timestamp', startOfToday.toISOString());

    return res.status(200).json({
      success: true,
      data: {
        total_licenses: totalLicenses || 0,
        active_devices: activeDevices || 0,
        total_devices: totalDevices || 0,
        todays_logs: todaysLogs || 0
      }
    });

  } catch (err: any) {
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
}
