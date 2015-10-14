import getPem from 'rsa-pem-from-mod-exp';

export default {
  getPem(jwks, kid) {
    const { n: modulus, e: exponent } = jwks.find((jwk) => jwk.kid === kid);
    return getPem(modulus, exponent);
  },
};
