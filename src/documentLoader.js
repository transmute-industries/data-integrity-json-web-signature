const contexts = require('./contexts');
const dids = require('./dids');

const documentLoader = (iri) => {
  const id = iri.split('#')[0];
  if (contexts[id]) {
    return {document: contexts[id]};
  }
  if (dids[id]) {
    return {document: dids[id]};
  }
  const message = '🔥 unsupported iri: ' + id;
  console.error(message);
  throw new Error(message);
};

module.exports = documentLoader;
