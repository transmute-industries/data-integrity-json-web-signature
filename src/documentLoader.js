const contexts = require('./contexts');

const documentLoader = (iri) => {
  if (contexts[iri]) {
    return {document: contexts[iri]};
  }
  const message = '🔥 unsupported iri: ' + iri;
  console.error(message);
  throw new Error(message);
};

module.exports = documentLoader;
