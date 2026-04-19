import { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import { verifyJWT } from '../lib/auth';
import { setCorsHeaders, handleCorsPreFlight } from '../lib/cors';

const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_KEY || ''
);

interface DashboardStats {
  total_licenses: number;
  active_licenses: number;
  total_devices: number;
  total_logins: number;
  failed_logins: number;
  success_rate: number;
}

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

    const { data: licenses } = await supabase.from('licenses').select('revoked');
    const { data: devices } = await supabase.from('devices').select('id', { count: 'exact' });
    const { data: logs } = await supabase.from('login_logs').select('status', { count: 'exact' });

    const totalLicenses = licenses?.length || 0;
    
    // Now an active key is just a key that hasn't been manually revoked
    const activeLicenses = licenses?.filter((l) => !l.revoked).length || 0;

    const totalLogins = logs?.length || 0;
    const failedLogins = logs?.filter((l) => l.status === 'failed' || l.status === 'failed_limit').length || 0;
    const successLogins = totalLogins - failedLogins;
    const successRate = totalLogins > 0 ? (successLogins / totalLogins) * 100 : 0;

    const stats: DashboardStats = {
      total_licenses: totalLicenses,
      active_licenses: activeLicenses,
      total_devices: devices?.length || 0,
      total_logins: totalLogins,
      failed_logins: failedLogins,
      success_rate: parseFloat(successRate.toFixed(2)),
    };

    return res.status(200).json({ success: true, data: stats });
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
}
