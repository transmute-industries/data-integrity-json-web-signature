const JsonWebKey2020 = require('./JsonWebKey2020');

const data = new TextEncoder().encode(
    'It’s a dangerous business, Frodo, going out your door. 🧠💎',
);

it('generate', async () => {
  const k = await JsonWebKey2020.generate('EdDSA');
  expect(k.id).toBeDefined();
  expect(k.type).toBeDefined();
  expect(k.controller).toBeDefined();
  expect(k.publicKeyJwk).toBeDefined();
  expect(k.privateKeyJwk).toBeDefined();
});

it('sign and verify', async () => {
  const k = await JsonWebKey2020.generate('EdDSA');
  const s = await k.sign(data);
  const v = await k.verify(data, s);
  expect(v).toBe(true);
});
