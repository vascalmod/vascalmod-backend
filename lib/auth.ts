import jwt, { Secret, SignOptions } from 'jsonwebtoken';



const JWT_SECRET: Secret =
  process.env.JWT_SECRET || '3ed92d36086fdf3a888cfc54812a83075fc9596b470d2df98a7f45c3d75b5b9d';
export interface TokenPayload {
  user_id?: string;
  license_key?: string;
  hwid?: string;
  is_admin?: boolean;
  email?: string;
  iat?: number;
  exp?: number;
}

export function verifyJWT(token: string, adminOnly = false): TokenPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;

    if (adminOnly && !decoded.is_admin) {
      return null;
    }

    return decoded;
  } catch (error) {
    return null;
  }
}
export function generateToken(
  payload: Omit<TokenPayload, 'iat' | 'exp'>,
  expiresIn: string = '24h'
): string {
  const options: SignOptions = {
    expiresIn: expiresIn as SignOptions['expiresIn'],
  };

  return jwt.sign(payload, JWT_SECRET, options);
}