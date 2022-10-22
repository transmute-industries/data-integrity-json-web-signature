const jsonld = require('jsonld');
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

it('can cannonize', async () => {
  const c = await jsonld.canonize(document, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    documentLoader,
  });
  console.log(c);
  expect(c).toBeDefined();
});
