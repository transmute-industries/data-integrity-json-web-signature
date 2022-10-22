const jose = require('jose');

const signDetached = async (data, privateKeyJwk) => {
  const privateKey = await jose.importJWK(privateKeyJwk);
  const jws = await new jose.CompactSign(data)
      .setProtectedHeader({
        alg: privateKeyJwk.alg,
        b64: false,
        crit: ['b64'],
      })
      .sign(privateKey);
  return jws;
};

const verifyDetached = async (data, jws, publicKeyJwk) => {
  const publicKey = await jose.importJWK(publicKeyJwk);
  const s = {
    protected: jws.split('..')[0],
    payload: data,
    signature: jws.split('..')[1],
  };
  const v = await jose.flattenedVerify(s, publicKey);
  return v.protectedHeader.alg === publicKeyJwk.alg;
};

module.exports = {signDetached, verifyDetached};
