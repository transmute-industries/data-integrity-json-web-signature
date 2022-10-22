const JsonWebKey2020 = require('./JsonWebKey2020');
const JsonWebSignature2020 = require('./JsonWebSignature2020');
const documentLoader = require('./documentLoader');

const document = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  'id': 'http://example.edu/credentials/1872',
  'type': ['VerifiableCredential', 'NewCredentialType'],
  'issuer': {
    id: 'did:example:123',
    type: ['Organization', 'OrganizationType'],
  },
  'issuanceDate': '2010-01-01T19:23:24Z',
  'credentialSubject': {
    id: 'did:example:456',
    type: ['Person', 'JobType'],
    claimName: 'It’s a dangerous business, Frodo, going out your door. 🧠💎',
  },
};

it('sign and verify', async () => {
  const key = await JsonWebKey2020.generate('EdDSA');
  const suite = new JsonWebSignature2020({key});
  const proof = await suite.getProof({document, documentLoader});
  const verified = await suite.verifyProof({document, proof, documentLoader});
  expect(verified).toBe(true);
});
