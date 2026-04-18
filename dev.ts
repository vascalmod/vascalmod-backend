// Create License
app.post('/api/licenses', async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];
    const verified = verifyJWT(token || '', true);

    if (!verified) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const action = req.query.action;

    // Revoke License
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
    // UPDATED: Now receives the custom 'expiration_days' dynamically
    const { 
      plan = '1D', 
      max_devices = 3, 
      expiration_days = null, 
      strict_mode = false 
    } = req.body;

    // Generate unique license key
    const licenseKey = `LIC-${Date.now()}-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;

    // Database query logic
    const expires_at = new Date();
    let daysToAdd = 1;

    if (plan === 'custom' && expiration_days) {
      daysToAdd = parseInt(expiration_days);
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

    // Supabase Insert execution
    const { data, error } = await supabase
      .from('licenses')
      .insert({
        key: licenseKey,
        plan,
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
    console.error('Error creating license:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
