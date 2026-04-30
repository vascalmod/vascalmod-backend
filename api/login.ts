import { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import { setCorsHeaders, handleCorsPreFlight } from '../lib/cors';

// Initialize Supabase (Checking both standard service key environment variable names)
const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || ''
);

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // 1. Handle CORS Preflight (Crucial for Vercel/Frontend communication)
  if (handleCorsPreFlight(req, res)) {
    return res;
  }
  
  // 2. Add CORS headers to the main response
  setCorsHeaders(res);

  // 3. Ensure this is a POST request
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { license_key, hwid, ip } = req.body;

    // Validate inputs
    if (!license_key || !hwid) {
      return res.status(400).json({ error: 'License key and HWID are required.' });
    }

    // --- STEP 1: Validate the License ---
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

    // --- STEP 2: Check if the Device (hwid) is already registered ---
    const { data: existingDevice, error: deviceError } = await supabase
      .from('devices')
      .select('*')
      .eq('license_key', license_key)
      .eq('hwid', hwid)
      .single();

    if (existingDevice) {
      // DEVICE EXISTS: Strictly check Expiry Date
      const now = new Date();
      const expiryDate = new Date(existingDevice.expires_at);

      if (now > expiryDate) {
        return res.status(403).json({ error: 'License Expired for this device.' });
      }

      // Update last_used and ip, but DO NOT touch the fixed expires_at date
      await supabase
        .from('devices')
        .update({ last_used: now.toISOString(), ip: ip || existingDevice.ip })
        .eq('id', existingDevice.id);

      return res.status(200).json({ 
        success: true,
        message: 'Login successful', 
        expires_at: existingDevice.expires_at 
      });
    }

    // --- STEP 3: Register New Device (Consume a slot) ---
    // Count exact active devices for this license
    const { count: activeDeviceCount, error: countError } = await supabase
      .from('devices')
      .select('*', { count: 'exact', head: true })
      .eq('license_key', license_key);

    if (countError) {
      throw countError;
    }

    // Block if max devices reached
    if ((activeDeviceCount || 0) >= license.max_devices) {
      return res.status(403).json({ 
        error: `Device limit reached. (${activeDeviceCount}/${license.max_devices} slots used)` 
      });
    }

    // Calculate the fixed expiration date based on the plan's duration
    const activationDate = new Date();
    const expirationDate = new Date();
    expirationDate.setDate(activationDate.getDate() + license.duration_days);

    // Insert the new device and lock in the expires_at date
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

    if (insertError) {
      throw insertError;
    }

    return res.status(200).json({ 
      success: true,
      message: 'Device activated successfully', 
      expires_at: newDevice.expires_at 
    });

  } catch (err: any) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
}
