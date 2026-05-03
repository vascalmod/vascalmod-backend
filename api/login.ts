import { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import { setCorsHeaders, handleCorsPreFlight } from '../lib/cors';

const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || ''
);

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (handleCorsPreFlight(req, res)) return res;
  setCorsHeaders(res);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { license_key, hwid } = req.body;
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || (req.headers['x-real-ip'] as string) || '0.0.0.0';

    if (!license_key || !hwid) {
      return res.status(400).json({ error: 'License key and HWID are required.' });
    }

    // 1. Validate the License
    const { data: license, error: licenseError } = await supabase
      .from('licenses')
      .select('*')
      .eq('key', license_key)
      .single();

    if (licenseError || !license) {
      return res.status(404).json({ error: 'Invalid license key.' });
    }

    if (license.revoked) {
      return res.status(403).json({ error: 'This license has been revoked.' });
    }

    // Helper function to record the login log quietly with geolocation
    const recordLoginLog = async () => {
      let geoData = { city: 'Unknown', country: 'Unknown', isp: 'Unknown' };
      if (ip && !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('127.')) {
          try {
              const geoRes = await fetch(`http://ip-api.com/json/${ip}`);
              if (geoRes.ok) {
                  const geoJson = await geoRes.json();
                  geoData = {
                      city: geoJson.city || 'Unknown',
                      country: geoJson.countryCode || geoJson.country || 'Unknown',
                      isp: geoJson.isp || 'Unknown'
                  };
              }
          } catch (e) { /* Ignore geo errors */ }
      }

      await supabase.from('login_logs').insert([{
        license_key: license_key,
        hwid: hwid,
        ip: ip || '0.0.0.0',
        status: 'success',
        city: geoData.city,
        country: geoData.country,
        isp: geoData.isp,
        timestamp: new Date().toISOString()
      }]);
    };

    // 2. Check if the Device exists
    const { data: existingDevice } = await supabase
      .from('devices')
      .select('*')
      .eq('license_key', license_key)
      .eq('hwid', hwid)
      .single();

    if (existingDevice) {
      const now = new Date();
      if (now > new Date(existingDevice.expires_at)) {
        return res.status(403).json({ error: 'License Expired for this device.' });
      }

      await supabase
        .from('devices')
        .update({ last_used: now.toISOString(), ip: ip || existingDevice.ip })
        .eq('id', existingDevice.id);

      await recordLoginLog(); // Trigger the log

      return res.status(200).json({ 
        success: true,
        message: 'Login successful', 
        plan: license.plan,         // FIX: Returns plan to terminal
        expires_at: existingDevice.expires_at 
      });
    }

    // 3. Register New Device
    const { count: activeDeviceCount } = await supabase
      .from('devices')
      .select('*', { count: 'exact', head: true })
      .eq('license_key', license_key);

    if ((activeDeviceCount || 0) >= license.max_devices) {
      return res.status(403).json({ 
        error: `Device limit reached. (${activeDeviceCount}/${license.max_devices} slots used)` 
      });
    }

    const activationDate = new Date();
    const expirationDate = new Date();
    // Use duration_seconds for precise control (minutes/hours), fallback to duration_days
    const durationSec = license.duration_seconds ?? (license.duration_days * 86400);
    expirationDate.setTime(activationDate.getTime() + (durationSec * 1000));

    const { data: newDevice, error: insertError } = await supabase
      .from('devices')
      .insert([{
        license_key: license_key,
        hwid: hwid,
        ip: ip || null,
        activated_at: activationDate.toISOString(),
        expires_at: expirationDate.toISOString(),
        last_used: activationDate.toISOString(),
        last_seen: activationDate.toISOString()
      }])
      .select()
      .single();

    if (insertError) throw insertError;

    await recordLoginLog(); // Trigger the log

    return res.status(200).json({ 
      success: true,
      message: 'Device activated successfully', 
      plan: license.plan,         // FIX: Returns plan to terminal
      expires_at: newDevice.expires_at 
    });

  } catch (err: any) {
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
}
