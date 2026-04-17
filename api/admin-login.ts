import { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import { setCorsHeaders, handleCorsPreFlight } from '../lib/cors';

const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_KEY || ''
);

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  // Handle CORS preflight
  if (handleCorsPreFlight(req, res)) {
    return res;
  }

  // Add CORS headers to all responses
  setCorsHeaders(res);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Use Supabase Auth to verify credentials
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error || !data.user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if user is admin
    const { data: adminData } = await supabase
      .from('admins')
      .select('id')
      .eq('user_id', data.user.id)
      .single();

    if (!adminData) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        user_id: data.user.id,
        email: data.user.email,
        is_admin: true,
      },
      process.env.JWT_SECRET || '3ed92d36086fdf3a888cfc54812a83075fc9596b470d2df98a7f45c3d75b5b9d',
      {
        expiresIn: '24h',
      }
    );

    return res.status(200).json({
      success: true,
      token,
      user: {
        id: data.user.id,
        email: data.user.email,
      },
    });
  } catch (error) {
    console.error('Admin login error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
