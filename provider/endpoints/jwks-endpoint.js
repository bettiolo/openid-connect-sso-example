export default (privateJwks) => {
  const publicJwks = {
    keys: [],
  };
  publicJwks.keys = privateJwks.keys.map(jwk => {
    delete jwk.d; // remove private exponent
    return jwk;
  });
  return (req, res) => res.json(publicJwks);
};
