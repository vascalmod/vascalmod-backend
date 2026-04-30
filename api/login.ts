import { createClient } from '@supabase/supabase-js';
// Initialize your Supabase client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

export async function handleLogin(req, res) {
  const { license_key, hwid, ip } = req.body;

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

  // 2. Check if the Device (hwid) is already registered to this license
  const { data: existingDevice, error: deviceError } = await supabase
    .from('devices')
    .select('*')
    .eq('license_key', license_key)
    .eq('hwid', hwid)
    .single();

  if (existingDevice) {
    // DEVICE EXISTS: Check Expiry Date strictly
    const now = new Date();
    const expiryDate = new Date(existingDevice.expires_at);

    if (now > expiryDate) {
      return res.status(403).json({ error: 'License Expired for this device.' });
    }

    // Update last_used and ip, but DO NOT TOUCH expires_at or activated_at
    await supabase
      .from('devices')
      .update({ last_used: new Date().toISOString(), ip: ip })
      .eq('id', existingDevice.id);

    return res.status(200).json({ 
      message: 'Login successful', 
      expires_at: existingDevice.expires_at 
    });
  }

  // 3. DEVICE DOES NOT EXIST: Try to register it (Consume a slot)
  // First, check how many devices are currently active for this license
  const { count: activeDeviceCount } = await supabase
    .from('devices')
    .select('*', { count: 'exact', head: true })
    .eq('license_key', license_key);

  if (activeDeviceCount >= license.max_devices) {
    return res.status(403).json({ 
      error: `Device limit reached. (${activeDeviceCount}/${license.max_devices} slots used)` 
    });
  }

  // Calculate the fixed expiration date based on the license's duration_days
  const activationDate = new Date();
  const expirationDate = new Date();
  expirationDate.setDate(activationDate.getDate() + license.duration_days);

  // Insert the new device, permanently locking in the expires_at date
  const { data: newDevice, error: insertError } = await supabase
    .from('devices')
    .insert([{
      license_key: license_key,
      hwid: hwid,
      ip: ip,
      activated_at: activationDate.toISOString(),
      expires_at: expirationDate.toISOString(),
      last_used: activationDate.toISOString(),
      last_seen: activationDate.toISOString()
    }])
    .select()
    .single();

  if (insertError) {
    return res.status(500).json({ error: 'Failed to activate device.' });
  }

  return res.status(200).json({ 
    message: 'Device activated successfully', 
    expires_at: newDevice.expires_at 
  });
}
