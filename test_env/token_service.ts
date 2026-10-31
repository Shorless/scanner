import * as crypto from 'crypto';
export const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
