import * as crypto from 'crypto';
export const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' /* [SHORLESS-PQC: Hybrider avec ML-KEM] */ });
