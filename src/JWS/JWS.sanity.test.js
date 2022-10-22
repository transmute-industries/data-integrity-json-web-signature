const jose = require('jose');

const data = new TextEncoder().encode(
    'It’s a dangerous business, Frodo, going out your door. 🧠💎',
);

it('sign and verify detached', async () => {
  const {privateKey, publicKey} = await jose.generateKeyPair('EdDSA');
  const s = await new jose.FlattenedSign(data)
      .setProtectedHeader({alg: 'EdDSA', b64: false, crit: ['b64']})
      .sign(privateKey);
  s.payload = data;
  const v = await jose.flattenedVerify(s, publicKey);
  expect(v.protectedHeader.alg).toBe('EdDSA');
});

const JWK = require('../JWK');
const JWS = require('./index');

it('signDetached & verifyDetached', async () => {
  const k = await JWK.generateKeyPair();
  const s = await JWS.signDetached(data, k.privateKeyJwk);
  const v = await JWS.verifyDetached(data, s, k.publicKeyJwk);
  expect(v).toBe(true);
});
