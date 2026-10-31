const crypto = require('crypto');
const { privateKey } = crypto./* [SHORLESS-PQC] */ generateKeyPairSync('rsa', { modulusLength: 2048 });
const hash = crypto.createHash('sha256').update('token').digest('hex');
