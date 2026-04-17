// Centralized configuration
export const JWT_SECRET = process.env.JWT_SECRET || '3ed92d36086fdf3a888cfc54812a83075fc9596b470d2df98a7f45c3d75b5b9d';

export const SUPABASE_URL = process.env.SUPABASE_URL || '';
export const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';

console.log('🔧 Constants loaded:');
console.log('   SUPABASE_URL:', SUPABASE_URL ? '✓ SET' : '✗ MISSING');
console.log('   SUPABASE_SERVICE_KEY:', SUPABASE_SERVICE_KEY ? '✓ SET' : '✗ MISSING');
console.log('   JWT_SECRET:', JWT_SECRET ? '✓ SET' : '✗ MISSING');
