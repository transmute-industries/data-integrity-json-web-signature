const jsonld = require('jsonld');
const crypto = require('crypto');

const JsonWebKey2020 = require('./JsonWebKey2020');

const sha256 = (input) => {
  return crypto.createHash('sha256').update(input).digest();
};

class JsonWebSignature2020 {
  constructor({key}) {
    this.key = key;
  }

  async createVerifyData({document, proof, documentLoader}) {
    const clonedDocument = JSON.parse(JSON.stringify(document));
    const clonedProof = JSON.parse(JSON.stringify(proof));
    delete clonedProof['jws'];
    const c14nProofOptions = await jsonld.canonize(clonedProof, {
      algorithm: 'URDNA2015',
      format: 'application/n-quads',
      documentLoader,
    });
    const c14nDocument = await jsonld.canonize(clonedDocument, {
      algorithm: 'URDNA2015',
      format: 'application/n-quads',
      documentLoader,
    });
    return Buffer.concat([sha256(c14nProofOptions), sha256(c14nDocument)]);
  }

  async getProof({document, documentLoader}) {
    const clonedDocument = JSON.parse(JSON.stringify(document));
    const proof = {
      '@context': clonedDocument['@context'],
      'type': 'JsonWebSignature2020',
    };
    const verifyData = await this.createVerifyData({
      document: clonedDocument,
      proof,
      documentLoader,
    });
    // console.log('sign: ', verifyData.toString('hex'));
    const signature = await this.key.sign(verifyData);
    proof.jws = signature;
    delete proof['@context'];
    return proof;
  }

  async addProof({document, documentLoader}) {
    const clonedDocument = JSON.parse(JSON.stringify(document));
    clonedDocument.proof = await this.getProof({
      document: clonedDocument,
      documentLoader,
    });
    return clonedDocument;
  }

  async verifyProof({document, proof, documentLoader}) {
    const clonedDocument = JSON.parse(JSON.stringify(document));
    const clonedProof = JSON.parse(JSON.stringify(proof));
    clonedProof['@context'] = clonedDocument['@context'];
    const verifyData = await this.createVerifyData({
      document: clonedDocument,
      proof: clonedProof,
      documentLoader,
    });
    // console.log('verify: ', verifyData.toString('hex'));
    const verified = await this.key.verify(verifyData, proof.jws);
    return verified;
  }
}

module.exports = JsonWebSignature2020;
