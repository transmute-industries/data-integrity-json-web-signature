const JWK = require('./index');

it('generateKeyPair', async () => {
  const k = await JWK.generateKeyPair();
  expect(k.publicKeyJwk).toBeDefined();
  expect(k.privateKeyJwk).toBeDefined();
});
