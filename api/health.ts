import { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import { setCorsHeaders, handleCorsPreFlight } from '../lib/cors';

const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_KEY || ''
);

/**
 * Health check endpoint
 * Used to verify API is running and Supabase connection works
 */
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

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Debug: Log environment variables
  console.log('SUPABASE_URL:', process.env.SUPABASE_URL ? 'SET' : 'NOT SET');
  console.log('SUPABASE_SERVICE_KEY:', process.env.SUPABASE_SERVICE_KEY ? 'SET' : 'NOT SET');

  try {
    // Test Supabase connection with a simpler query
    const { data: testData, error: testError, status } = await supabase
      .from('licenses')
      .select('*', { count: 'exact', head: true });

    console.log('Query status:', status);
    console.log('Query error:', JSON.stringify(testError));
    console.log('Query data:', testData);

    if (testError) {
      console.error('Full Supabase error:', testError);
      return res.status(503).json({
        status: 'unhealthy',
        error: 'Database connection failed',
        timestamp: new Date().toISOString(),
        debug: {
          supabaseUrlSet: !!process.env.SUPABASE_URL,
          supabaseKeySet: !!process.env.SUPABASE_SERVICE_KEY,
          errorMessage: testError.message || 'Unknown error',
          errorCode: testError.code || 'NO_CODE',
          errorDetails: testError.details || 'No details',
          errorHint: testError.hint || 'No hint',
          fullError: JSON.stringify(testError),
          queryStatus: status,
        }
      });
    }

    return res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: '1.0.0',
      features: [
        'login',
        'licenses',
        'logs',
        'admin-login',
        'stats',
      ],
    });
  } catch (error) {
    console.error('Health check error:', error);
    return res.status(500).json({
      status: 'unhealthy',
      error: 'Internal server error',
      timestamp: new Date().toISOString(),
    });
  }
}
